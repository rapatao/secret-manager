package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
)

const cliPolicy = `{"enabled":true,"namespaces":{"team-a":{"paths":["/apps"]}}}`

func newPolicyHarness(t *testing.T) *harness {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	h := newHarnessOn(t, backend, backend)
	h.srv.SyncPolicy = syncpolicy.New(backend, nil)
	h.srv.PolicyPreview = func(_ context.Context, p storage.SyncPolicy) ([]string, error) {
		var out []string
		for ns := range p.Namespaces {
			out = append(out, ns+"/app: path not allowed")
		}
		return out, nil
	}
	return h
}

func TestSyncPolicyGetSet(t *testing.T) {
	h := newPolicyHarness(t)
	h.stdin = cliPolicy
	if code := h.run("sync-policy", "set", "--file", "-"); code != 1 {
		t.Fatalf("exit %d, stderr: %s", code, h.stderr.String())
	}
	for _, want := range []string{"disallows 1 SecretSyncs", "team-a/app: path not allowed", "--confirm"} {
		if !strings.Contains(h.stderr.String(), want) {
			t.Fatalf("stderr lacks %q:\n%s", want, h.stderr.String())
		}
	}
	if out := h.mustRun("sync-policy", "get"); strings.Contains(out, "team-a") {
		t.Fatalf("saved without confirmation:\n%s", out)
	}

	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(cliPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := h.mustRun("sync-policy", "set", "--file", file, "--confirm"); !strings.Contains(out, `"team-a"`) {
		t.Fatalf("set output:\n%s", out)
	}
	if out := h.mustRun("sync-policy", "get"); !strings.Contains(out, `"enabled": true`) || !strings.Contains(out, "/apps") {
		t.Fatalf("get output:\n%s", out)
	}
}

func TestSyncPolicySetRejectsBadDocument(t *testing.T) {
	h := newPolicyHarness(t)
	h.stdin = `{"enabled":true,"bogus":1}`
	if code := h.run("sync-policy", "set", "--file", "-"); code != 2 {
		t.Fatalf("exit %d, stderr: %s", code, h.stderr.String())
	}
	if code := h.run("sync-policy"); code != 2 {
		t.Fatalf("exit %d", code)
	}

	for _, doc := range []string{cliPolicy + "}", cliPolicy + "]", cliPolicy + " {}"} {
		h.stdin = doc
		if code := h.run("sync-policy", "set", "--file", "-"); code != 2 || !strings.Contains(h.stderr.String(), "stdin") || !strings.Contains(h.stderr.String(), "unexpected data after the document") {
			t.Fatalf("%q: exit %d, stderr: %s", doc, code, h.stderr.String())
		}
	}

	h.stdin = `{"enabled":true,"bogus":1}`
	h.run("sync-policy", "set", "--file", "-")
	if !strings.Contains(h.stderr.String(), "stdin") || !strings.Contains(h.stderr.String(), "unknown field") {
		t.Fatalf("stderr: %s", h.stderr.String())
	}

	h.stdin = cliPolicy + "\n\n"
	if code := h.run("sync-policy", "set", "--file", "-", "--confirm"); code != 0 {
		t.Fatalf("trailing newline rejected: exit %d, stderr: %s", code, h.stderr.String())
	}
}

func TestSyncPolicySetNeedsFileBeforeAnyRequest(t *testing.T) {
	h := newPolicyHarness(t)
	h.envURL = "http://127.0.0.1:1"
	h.stdin = cliPolicy
	if code := h.run("sync-policy", "set"); code != 2 || !strings.Contains(h.stderr.String(), "needs --file FILE") {
		t.Fatalf("exit %d, stderr: %s", code, h.stderr.String())
	}
}

func TestSyncPolicyUnavailable(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"get"}, {"set", "--file", "-"}} {
		sub := args[0]
		if code := h.run(append([]string{"sync-policy"}, args...)...); code != 1 || !strings.Contains(h.stderr.String(), "sync-policy capability") {
			t.Fatalf("%s: exit %d, stderr: %s", sub, code, h.stderr.String())
		}
	}
}
