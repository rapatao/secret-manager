package cli

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/client"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/tokens"
)

const token = "0123456789abcdef0123456789abcdef"

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

type harness struct {
	t        *testing.T
	ts       *httptest.Server
	env      map[string]string
	url      string
	envURL   string
	envToken string
	dir      string
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	stdin    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	svc := secrets.New(backend, nil)
	svc.KeepVersions = 10
	srv, err := server.New(svc, tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	srv.Version = "1.4.0"
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, ts: ts, env: map[string]string{}, url: ts.URL, envURL: ts.URL, envToken: token, dir: t.TempDir()}
}

// withToken returns a harness for the same server using token.
func (h *harness) withToken(token string) *harness {
	return &harness{t: h.t, ts: h.ts, env: map[string]string{}, url: h.url, envURL: h.envURL, envToken: token, dir: h.t.TempDir()}
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	env := map[string]string{EnvURL: h.envURL, EnvToken: h.envToken}
	maps.Copy(env, h.env)
	c := &CLI{
		Stdin:     strings.NewReader(h.stdin),
		Stdout:    &h.stdout,
		Stderr:    &h.stderr,
		Getenv:    func(k string) string { return env[k] },
		Environ:   func() []string { return []string{"PATH=/usr/bin:/bin", "KEEP=1", "OVERRIDE=old"} },
		ConfigDir: h.dir,
		Version:   "1.5.0",
	}
	return c.Run(context.Background(), args)
}

func (h *harness) mustRun(args ...string) string {
	h.t.Helper()
	if code := h.run(args...); code != 0 {
		h.t.Fatalf("%v: exit %d, stderr: %s", args, code, h.stderr.String())
	}
	return h.stdout.String()
}

func TestSetGetListDelete(t *testing.T) {
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "A=1", "B=x=y")
	h.mustRun("set", "--path", "/tools/nested", "C=3")

	if got := h.mustRun("list"); got != "/tools\n/tools/nested\n" {
		t.Fatalf("list: %q", got)
	}
	if got := h.mustRun("get", "--path", "/tools", "B"); got != "x=y\n" {
		t.Fatalf("get key: %q", got)
	}
	if got := h.mustRun("get", "--path", "/tools", "--recursive"); got != "A=\"1\"\nB=\"x=y\"\nC=\"3\"\n" {
		t.Fatalf("get recursive: %q", got)
	}
	if code := h.run("get", "--path", "/tools", "MISSING"); code != 1 {
		t.Fatalf("get missing key: exit %d", code)
	}

	h.mustRun("delete", "--path", "/tools", "A")
	if got := h.mustRun("get", "--path", "/tools"); got != "B=\"x=y\"\n" {
		t.Fatalf("after delete: %q", got)
	}
	h.mustRun("delete", "--path", "/tools", "--all")
	if got := h.mustRun("list"); got != "/tools/nested\n" {
		t.Fatalf("after delete --all: %q", got)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "A=1")
	h.mustRun("set", "--path", "/tools", "A=2", "B=3")

	out := h.mustRun("history", "--path", "/tools")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "2 ") || !strings.HasSuffix(lines[1], " A,B") {
		t.Fatalf("history: %q", out)
	}
	if got := h.mustRun("history", "--path", "/tools", "1"); got != "A=\"1\"\n" {
		t.Fatalf("history version: %q", got)
	}
	if got := h.mustRun("history", "--path", "/tools", "--diff", "1"); got != "~ A\n+ B\n" {
		t.Fatalf("diff to current: %q", got)
	}
	if got := h.mustRun("history", "--path", "/tools", "--diff", "2", "1"); got != "~ A\n- B\n" {
		t.Fatalf("diff between versions: %q", got)
	}
	h.mustRun("rollback", "--path", "/tools", "1")
	if got := h.mustRun("get", "--path", "/tools"); got != "A=\"1\"\n" {
		t.Fatalf("after rollback: %q", got)
	}
	for _, args := range [][]string{
		{"rollback", "--path", "/tools"},
		{"rollback", "--path", "/tools", "x"},
		{"history", "--path", "/tools", "1", "2"},
		{"history", "--path", "/tools", "--diff"},
		{"history", "--path", "/tools", "--diff", "1", "2", "3"},
	} {
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := h.run("rollback", "--path", "/tools", "9"); code != 1 {
		t.Errorf("rollback missing version: exit %d, want 1", code)
	}
}

func TestSetFromEnvFileAndExport(t *testing.T) {
	h := newHarness(t)
	h.stdin = "# comment\nexport USER='bob'\nMULTI=\"a\\nb $x\"\n"
	h.mustRun("set", "--path", "/app", "--env-file", "-")

	if got := h.mustRun("export", "--path", "/app", "--format", "json"); got != "{\n  \"MULTI\": \"a\\nb $x\",\n  \"USER\": \"bob\"\n}\n" {
		t.Fatalf("json export: %q", got)
	}
	if got := h.mustRun("export", "--path", "/app"); got != "MULTI=\"a\\nb \\$x\"\nUSER=\"bob\"\n" {
		t.Fatalf("dotenv export: %q", got)
	}
}

func TestRunInjectsEnvAndForwardsExitCode(t *testing.T) {
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "OVERRIDE=new", "TOKEN=t0k")

	code := h.run("run", "--path", "/tools", "--", "sh", "-c", `printf '%s %s %s' "$KEEP" "$OVERRIDE" "$TOKEN"; exit 3`)
	if code != 3 {
		t.Fatalf("exit %d, stderr %s", code, h.stderr.String())
	}
	if got := h.stdout.String(); got != "1 new t0k" {
		t.Fatalf("stdout %q", got)
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	cases := [][]string{
		{},
		{"nope"},
		{"get"},
		{"set", "--path", "/x"},
		{"set", "--path", "/x", "novalue"},
		{"delete", "--path", "/x"},
		{"run", "--path", "/x"},
		{"export", "--path", "/x", "--format", "yaml"},
		{"list", "--unknown"},
		{"list", "extra"},
	}
	for _, args := range cases {
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestServerErrorsAreReported(t *testing.T) {
	h := newHarness(t)
	if code := h.run("get", "--path", "/missing"); code != 1 || !strings.Contains(h.stderr.String(), "404") {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestDotenvRoundTrip(t *testing.T) {
	in := map[string]string{"A": `quote " back \ dollar $HOME`, "B": "line1\nline2\r\n", "C": ""}
	var buf bytes.Buffer
	if err := formatDotenv(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := parseDotenv(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(in, out) {
		t.Fatalf("round trip: got %q, want %q", out, in)
	}
}

func TestParseDotenvErrors(t *testing.T) {
	for _, in := range []string{"NOEQUALS", `A="trailing\"`} {
		if _, err := parseDotenv(strings.NewReader(in)); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"A=1", "B=2"}, map[string]string{"B": "3", "C": "4"})
	slices.Sort(got)
	if want := []string{"A=1", "B=3", "C=4"}; !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestServerFlag(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/app", "A=1")

	h.envURL, h.envToken = "", ""
	if code := h.run("list"); code != 2 || !strings.Contains(h.stderr.String(), "give --server, set "+EnvURL) {
		t.Fatalf("missing server: exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("list", "--server", h.url); code != 2 || !strings.Contains(h.stderr.String(), "no token for "+h.url) {
		t.Fatalf("no stored token: exit %d, stderr %q", code, h.stderr.String())
	}

	h.envURL, h.envToken = h.url, token
	if got := h.mustRun("get", "--server", h.url+"/", "--path", "/app", "A"); got != "1\n" {
		t.Fatalf("--server matching %s must use %s: %q", EnvURL, EnvToken, got)
	}
}

func TestEnvTokenOnlyGoesToEnvURL(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/app", "A=1")

	h.envURL, h.envToken = "", ""
	h.stdin = token
	h.mustRun("servers", "login", "--server", h.url, "--token-stdin")

	h.envURL, h.envToken = "https://other.example", "token-for-other"
	if got := h.mustRun("list", "--server", h.url); got != "/app\n" {
		t.Fatalf("--server must use its stored token, not %s: %q", EnvToken, got)
	}

	h.envURL = ""
	if code := h.run("list"); code != 2 || !strings.Contains(h.stderr.String(), EnvToken+" is set but "+EnvURL+" is not") {
		t.Fatalf("token without URL: exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestLoginUsesKeychainAndDefaultServer(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/app", "A=1")
	h.envURL, h.envToken = "", ""

	h.stdin = "wrong-token\n"
	if code := h.run("servers", "login", "--server", h.url, "--token-stdin"); code != 1 || !strings.Contains(h.stderr.String(), "invalid token") {
		t.Fatalf("bad token: exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("list"); code != 2 {
		t.Fatalf("failed login must store nothing: exit %d", code)
	}

	h.stdin = token + "\n"
	if got := h.mustRun("servers", "login", "--server", h.url+"/", "--token-stdin"); got != "Logged in to "+h.url+"\n" {
		t.Fatalf("login output %q", got)
	}
	if stored, err := keyring.Get(keyringService, h.url); err != nil || stored != token {
		t.Fatalf("keychain token %q, %v", stored, err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "credentials.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file written although keychain works: %v", err)
	}
	if got := h.mustRun("list"); got != "/app\n" {
		t.Fatalf("list with stored login: %q", got)
	}

	h.mustRun("servers", "logout")
	if _, err := keyring.Get(keyringService, h.url); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("token still in keychain: %v", err)
	}
	if code := h.run("list"); code != 2 {
		t.Fatalf("list after logout: exit %d", code)
	}
}

func TestLoginFallsBackToFile(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(keyring.MockInit)
	h := newHarness(t)
	h.mustRun("set", "--path", "/app", "A=1")
	h.envURL, h.envToken = "", ""

	h.stdin = token
	h.mustRun("servers", "login", "--server", h.url, "--token-stdin")
	if !strings.Contains(h.stderr.String(), "keychain unavailable") {
		t.Fatalf("missing fallback warning: %q", h.stderr.String())
	}
	info, err := os.Stat(filepath.Join(h.dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials.json permissions %o", perm)
	}
	if got := h.mustRun("list"); got != "/app\n" {
		t.Fatalf("list with file token: %q", got)
	}

	h.mustRun("servers", "logout", "--server", h.url)
	if code := h.run("list", "--server", h.url); code != 2 {
		t.Fatalf("list after logout: exit %d", code)
	}
}

func TestLoginRequiresTerminalOrStdinFlag(t *testing.T) {
	h := newHarness(t)
	if code := h.run("servers", "login", "--server", h.url); code != 2 || !strings.Contains(h.stderr.String(), "--token-stdin") {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestEnvTokenWinsOverStoredToken(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	if err := keyring.Set(keyringService, h.url, "stale-token"); err != nil {
		t.Fatal(err)
	}
	h.mustRun("list")
}

func TestServersListAndUse(t *testing.T) {
	keyring.MockInit()
	other := newHarness(t)
	h := newHarness(t)
	h.mustRun("set", "--path", "/home", "A=1")
	other.mustRun("set", "--path", "/other", "B=2")
	h.envURL, h.envToken = "", ""

	for _, url := range []string{h.url, other.url} {
		h.stdin = token
		h.mustRun("servers", "login", "--server", url, "--token-stdin")
	}

	want := []string{h.url, other.url + " (default)"}
	if h.url > other.url {
		want = []string{other.url + " (default)", h.url}
	}
	if got := h.mustRun("servers"); got != strings.Join(want, "\n")+"\n" {
		t.Fatalf("servers: %q", got)
	}
	if got := h.mustRun("list"); got != "/other\n" {
		t.Fatalf("list on default: %q", got)
	}
	if got := h.mustRun("list", "--server", h.url); got != "/home\n" {
		t.Fatalf("list with --server: %q", got)
	}

	if got := h.mustRun("servers", "use", h.url+"/"); got != "Default server is "+h.url+"\n" {
		t.Fatalf("use output %q", got)
	}
	if got := h.mustRun("list"); got != "/home\n" {
		t.Fatalf("list after use: %q", got)
	}
	if code := h.run("servers", "use", "https://unknown.example"); code != 1 || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("use unknown: exit %d, stderr %q", code, h.stderr.String())
	}

	h.mustRun("servers", "logout", "--server", other.url)
	if got := h.mustRun("servers", "list"); got != h.url+" (default)\n" {
		t.Fatalf("after logout of non-default: %q", got)
	}
	if code := h.run("servers", "bogus"); code != 2 {
		t.Fatalf("unknown subcommand: exit %d", code)
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t)
	want := "client: 1.5.0\nserver: 1.4.0 (" + h.url + ")\ncapabilities: backup, history, paths, secrets, tokens\n"
	if got := h.mustRun("version"); got != want {
		t.Fatalf("version: %q", got)
	}

	h.envURL, h.envToken = "", ""
	if got := h.mustRun("version"); got != "client: 1.5.0\n" {
		t.Fatalf("version without server: %q", got)
	}
}

func TestVersionAgainstServerWithoutInfo(t *testing.T) {
	h := newHarness(t)
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	h.envURL = ts.URL
	want := "client: 1.5.0\nserver: unknown, older than the client (" + ts.URL + ")\ncapabilities: history, paths, secrets\n"
	if got := h.mustRun("version"); got != want {
		t.Fatalf("version: %q", got)
	}
}

func TestBackupRestore(t *testing.T) {
	src := newHarness(t)
	src.mustRun("set", "--path", "/tools", "A=1")
	src.mustRun("set", "--path", "/tools", "A=2")
	file := filepath.Join(src.dir, "backup.json")
	src.mustRun("backup", "--history", "--output", file)
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file: %v %v", fi, err)
	}
	if out := src.mustRun("backup"); !strings.Contains(out, `"path":"/tools"`) || strings.Contains(out, `"versions"`) {
		t.Fatalf("backup to stdout: %s", out)
	}

	dst := newHarness(t)
	if got := dst.mustRun("restore", file); got != "Restored 1 paths\n" {
		t.Fatalf("restore: %q", got)
	}
	if got := dst.mustRun("get", "--path", "/tools", "A"); got != "2\n" {
		t.Fatalf("restored value: %q", got)
	}
	if got := dst.mustRun("history", "--path", "/tools"); strings.Count(got, "\n") != 3 {
		t.Fatalf("restored history: %q", got)
	}

	dst.stdin = "not json"
	if code := dst.run("restore", "-"); code != 1 || !strings.Contains(dst.stderr.String(), "is not a JSON backup") {
		t.Fatalf("restore invalid: %d %s", code, dst.stderr.String())
	}
}

func TestBackupNeedsCapability(t *testing.T) {
	h := newHarness(t)
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	h.envURL = ts.URL
	if code := h.run("backup"); code != 1 || !strings.Contains(h.stderr.String(), "does not support backup; upgrade the server") {
		t.Fatalf("backup on old server: %d %s", code, h.stderr.String())
	}
}

func TestOfflineCache(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "A=1")
	h.mustRun("get", "--path", "/tools", "A")
	h.mustRun("get", "--path", "/tools", "--recursive")

	entries, _ := filepath.Glob(filepath.Join(h.dir, "cache", "*", "*"))
	if len(entries) != 2 {
		t.Fatalf("cache entries %v", entries)
	}
	for _, e := range entries {
		b, _ := os.ReadFile(e)
		fi, _ := os.Stat(e)
		if bytes.Contains(b, []byte(`"A"`)) || fi.Mode().Perm() != 0o600 {
			t.Fatalf("entry %s not encrypted or not 0600: %o %q", e, fi.Mode().Perm(), b)
		}
	}

	h.envToken = "wrong-token-wrong-token-wrong-token"
	if code := h.run("get", "--path", "/tools", "A"); code != 1 || strings.Contains(h.stdout.String(), "1") {
		t.Fatalf("401 must not use the cache: %d %q", code, h.stdout.String())
	}
	h.envToken = token

	h.ts.Close()
	if got := h.mustRun("get", "--path", "/tools", "A"); got != "1\n" || !strings.Contains(h.stderr.String(), "unreachable") {
		t.Fatalf("offline get: %q, stderr %q", got, h.stderr.String())
	}
	if got := h.mustRun("run", "--path", "/tools", "--recursive", "--", "sh", "-c", "echo $A"); got != "1\n" {
		t.Fatalf("offline run: %q", got)
	}
	if code := h.run("get", "--path", "/other"); code != 1 {
		t.Fatalf("uncached path offline: exit %d", code)
	}

	h.env[EnvCacheMaxAge] = "1ns"
	if code := h.run("get", "--path", "/tools", "A"); code != 1 {
		t.Fatalf("expired entry used: exit %d", code)
	}
	h.env[EnvCacheMaxAge] = "soon"
	if code := h.run("get", "--path", "/tools", "A"); code != 2 {
		t.Fatalf("invalid max age: exit %d", code)
	}
}

func TestOfflineCacheDisabled(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "A=1")
	h.env[EnvCacheMaxAge] = "0"
	h.mustRun("get", "--path", "/tools", "A")
	if _, err := os.Stat(filepath.Join(h.dir, "cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache written while disabled: %v", err)
	}

	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(keyring.MockInit)
	delete(h.env, EnvCacheMaxAge)
	h.mustRun("get", "--path", "/tools", "A")
	if _, err := os.Stat(filepath.Join(h.dir, "cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache written without keychain: %v", err)
	}
}

func TestLogoutClearsCache(t *testing.T) {
	keyring.MockInit()
	h := newHarness(t)
	h.mustRun("set", "--path", "/tools", "A=1")
	h.envURL, h.envToken = "", ""
	h.stdin = token + "\n"
	h.mustRun("servers", "login", "--server", h.url, "--token-stdin")
	h.mustRun("get", "--path", "/tools", "A")
	if entries, _ := filepath.Glob(filepath.Join(h.dir, "cache", "*", "*")); len(entries) != 1 {
		t.Fatalf("cache entries %v", entries)
	}
	h.mustRun("servers", "logout")
	if entries, _ := filepath.Glob(filepath.Join(h.dir, "cache", "*", "*")); len(entries) != 0 {
		t.Fatalf("logout left %v", entries)
	}
}

func TestUnreachable(t *testing.T) {
	ctx := context.Background()
	for err, want := range map[error]bool{
		errors.New("dial tcp: connection refused"):     true,
		&client.Error{Status: http.StatusBadGateway}:   true,
		&client.Error{Status: http.StatusUnauthorized}: false,
		&client.Error{Status: http.StatusNotFound}:     false,
	} {
		if got := unreachable(ctx, err); got != want {
			t.Errorf("unreachable(%v) = %v", err, got)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if unreachable(canceled, errors.New("context canceled")) {
		t.Error("canceled context must not fall back")
	}
}

func TestTokens(t *testing.T) {
	h := newHarness(t)
	h.mustRun("set", "--path", "/app", "A=1")
	h.mustRun("set", "--path", "/other", "B=2")

	secret := strings.TrimSpace(h.mustRun("tokens", "create", "--name", "ci", "--path", "/app", "--read-only"))
	if !strings.HasPrefix(secret, tokens.Prefix) {
		t.Fatalf("created token %q", secret)
	}
	out := h.mustRun("tokens")
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "ci    /app  read-only") {
		t.Fatalf("tokens list: %q", out)
	}

	scoped := h.withToken(secret)
	if got := scoped.mustRun("get", "--path", "/app", "A"); got != "1\n" {
		t.Fatalf("scoped get: %q", got)
	}
	if got := scoped.mustRun("list"); got != "/app\n" {
		t.Fatalf("scoped list: %q", got)
	}
	if code := scoped.run("get", "--path", "/other"); code != 1 {
		t.Fatalf("scoped get outside path: exit %d", code)
	}
	if code := scoped.run("set", "--path", "/app", "A=2"); code != 1 {
		t.Fatalf("read-only set: exit %d", code)
	}

	h.mustRun("tokens", "revoke", "ci")
	if code := scoped.run("list"); code != 1 {
		t.Fatalf("revoked token: exit %d", code)
	}
	for _, args := range [][]string{
		{"tokens", "create", "--name", "x"},
		{"tokens", "revoke"},
		{"tokens", "list", "extra"},
		{"tokens", "bogus"},
	} {
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
