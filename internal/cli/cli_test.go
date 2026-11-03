package cli

import (
	"bytes"
	"context"
	"maps"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

const token = "0123456789abcdef0123456789abcdef"

type harness struct {
	t      *testing.T
	url    string
	stdout bytes.Buffer
	stderr bytes.Buffer
	stdin  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	svc := secrets.New(k8sstorage.New(fake.NewClientBuilder().Build(), "sm"), nil)
	srv, err := server.New(svc, token)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, url: ts.URL}
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	env := map[string]string{EnvURL: h.url, EnvToken: token}
	c := &CLI{
		Stdin:   strings.NewReader(h.stdin),
		Stdout:  &h.stdout,
		Stderr:  &h.stderr,
		Getenv:  func(k string) string { return env[k] },
		Environ: func() []string { return []string{"PATH=/usr/bin:/bin", "KEEP=1", "OVERRIDE=old"} },
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
