package cli

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

const token = "0123456789abcdef0123456789abcdef"

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

type harness struct {
	t        *testing.T
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
	svc := secrets.New(k8sstorage.New(fake.NewClientBuilder().Build(), "sm"), nil)
	svc.KeepVersions = 10
	srv, err := server.New(svc, token)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, url: ts.URL, envURL: ts.URL, envToken: token, dir: t.TempDir()}
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	env := map[string]string{EnvURL: h.envURL, EnvToken: h.envToken}
	c := &CLI{
		Stdin:     strings.NewReader(h.stdin),
		Stdout:    &h.stdout,
		Stderr:    &h.stderr,
		Getenv:    func(k string) string { return env[k] },
		Environ:   func() []string { return []string{"PATH=/usr/bin:/bin", "KEEP=1", "OVERRIDE=old"} },
		ConfigDir: h.dir,
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
	h.mustRun("rollback", "--path", "/tools", "1")
	if got := h.mustRun("get", "--path", "/tools"); got != "A=\"1\"\n" {
		t.Fatalf("after rollback: %q", got)
	}
	for _, args := range [][]string{
		{"rollback", "--path", "/tools"},
		{"rollback", "--path", "/tools", "x"},
		{"history", "--path", "/tools", "1", "2"},
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
