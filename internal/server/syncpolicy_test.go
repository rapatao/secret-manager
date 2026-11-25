package server

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
)

func newPolicyServer(t *testing.T, preview func(context.Context, storage.SyncPolicy) ([]string, error), controller bool) (string, *http.Client, *syncpolicy.Store, *int) {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	calls := 0
	store := syncpolicy.New(backend, func() { calls++ })
	ts, _ := newLoggedServer(t, func(s *Server) {
		s.SyncPolicy = store
		s.PolicyPreview = preview
		s.Settings.Controller = controller
	})
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	return ts.URL, c, store, &calls
}

func previewByPaths(_ context.Context, p storage.SyncPolicy) ([]string, error) {
	var out []string
	for ns, rule := range p.Namespaces {
		for _, path := range rule.Paths {
			out = append(out, ns+"/app: denied: "+path)
		}
	}
	slices.Sort(out)
	return out, nil
}

var digestRe = regexp.MustCompile(`name="digest" value="([0-9a-f]+)"`)

func digestOf(t *testing.T, body string) string {
	t.Helper()
	m := digestRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no digest in page:\n%s", body)
	}
	return m[1]
}

type failingPut struct{ storage.Backend }

func (failingPut) PutSyncPolicy(context.Context, storage.SyncPolicy) error {
	return errors.New("storage down")
}

func TestSyncPolicyDigestIgnoresPreviewOrder(t *testing.T) {
	calls := 0
	set := []string{"a/x: denied", "a/y: denied", "a/z: denied"}
	preview := func(context.Context, storage.SyncPolicy) ([]string, error) {
		calls++
		out := slices.Clone(set)
		if calls%2 == 0 {
			slices.Reverse(out)
		}
		return out, nil
	}
	base, c, store, _ := newPolicyServer(t, preview, true)
	f := policyForm(true, "a", "/x", "")
	_, body := post(t, c, base, f)
	f.Set("digest", digestOf(t, body))
	f.Set("confirm", "delete")
	post(t, c, base, f)
	if p, _ := store.Get(context.Background()); !p.Enabled {
		t.Fatal("confirming POST was rejected because the preview order changed")
	}
}

func TestSyncPolicyDifferentSetMismatches(t *testing.T) {
	calls := 0
	preview := func(context.Context, storage.SyncPolicy) ([]string, error) {
		calls++
		if calls == 1 {
			return []string{"a/x: denied"}, nil
		}
		return []string{"a/x: denied", "a/y: denied"}, nil
	}
	base, c, store, _ := newPolicyServer(t, preview, true)
	f := policyForm(true, "a", "/x", "")
	_, body := post(t, c, base, f)
	f.Set("digest", digestOf(t, body))
	f.Set("confirm", "delete")
	if _, body = post(t, c, base, f); !strings.Contains(body, "a/y: denied") {
		t.Fatalf("new list not shown:\n%s", body)
	}
	if p, _ := store.Get(context.Background()); p.Enabled {
		t.Fatal("saved although the denied set changed")
	}
}

func TestSyncPolicyPreviewErrorSavesNothing(t *testing.T) {
	base, c, store, _ := newPolicyServer(t, func(context.Context, storage.SyncPolicy) ([]string, error) {
		return nil, errors.New("list failed")
	}, true)
	if code, _ := post(t, c, base, policyForm(true, "a", "/x", "")); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	if p, _ := store.Get(context.Background()); p.Enabled {
		t.Fatal("saved after a preview error")
	}
}

func TestSyncPolicyAlreadyDisallowedNotListed(t *testing.T) {
	base, c, _, _ := newPolicyServer(t, previewByPaths, true)
	f := policyForm(true, "a", "/x", "")
	_, body := post(t, c, base, f)
	f.Set("confirm", "delete")
	f.Set("digest", digestOf(t, body))
	post(t, c, base, f)

	g := policyForm(true, "a", "/x /y", "")
	_, body = post(t, c, base, g)
	if strings.Contains(body, "denied: /x") || !strings.Contains(body, "denied: /y") {
		t.Fatalf("list should hold only the new denial:\n%s", body)
	}
}

func TestSyncPolicyRowsAndRemove(t *testing.T) {
	base, c, store, _ := newPolicyServer(t, nil, true)
	f := url.Values{
		"namespace": {"a", "b", "", ""}, "paths": {"/a", "/b", "", ""}, "targets": {"", "", "", ""},
		"remove": {"0"}, "enabled": {"true"},
	}
	post(t, c, base, f)
	p, _ := store.Get(context.Background())
	if len(p.Namespaces) != 1 || !slices.Equal(p.Namespaces["b"].Paths, []string{"/b"}) {
		t.Fatalf("policy %+v", p)
	}
	if code, _ := post(t, c, base, url.Values{"enabled": {"true"}}); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if p, _ = store.Get(context.Background()); len(p.Namespaces) != 1 {
		t.Fatalf("a form without rows replaced the policy: %+v", p)
	}
}

func TestSyncPolicyFailedPutIsAudited(t *testing.T) {
	backend := failingPut{k8sstorage.New(fake.NewClientBuilder().Build(), "sm")}
	ts, _ := newLoggedServer(t, func(s *Server) { s.SyncPolicy = syncpolicy.New(backend, nil) })
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	if code, _ := post(t, c, ts.URL, policyForm(true, "a", "/x", "")); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	_, body := get(t, c, ts.URL+"/audit")
	if !strings.Contains(body, "<code>enable_sync_policy</code>") || !strings.Contains(body, "storage down") {
		t.Fatalf("failed save not audited:\n%s", body)
	}
}

func policyForm(enabled bool, ns, paths, targets string) url.Values {
	f := url.Values{"namespace": {ns, ""}, "paths": {paths, ""}, "targets": {targets, ""}}
	if enabled {
		f.Set("enabled", "true")
	}
	return f
}

var baseRe = regexp.MustCompile(`name="base" value="([0-9a-f]*)"`)

func post(t *testing.T, c *http.Client, base string, form url.Values) (int, string) {
	t.Helper()
	if !form.Has("base") {
		form = maps.Clone(form)
		_, page := get(t, c, base+"/sync-policy")
		m := baseRe.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no base in page:\n%s", page)
		}
		form.Set("base", m[1])
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/sync-policy", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestSyncPolicyRequiresSessionAndSameOrigin(t *testing.T) {
	base, c, _, _ := newPolicyServer(t, nil, true)
	anon := &http.Client{Transport: c.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := anon.Get(base + "/sync-policy")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/login") {
		t.Fatalf("no session: %d %s", res.StatusCode, res.Header.Get("Location"))
	}

	req, _ := http.NewRequest(http.MethodPost, base+"/sync-policy", strings.NewReader(policyForm(true, "a", "/x", "").Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", res.StatusCode)
	}
}

func TestSyncPolicyInvalidSavesNothing(t *testing.T) {
	base, c, store, calls := newPolicyServer(t, nil, true)
	for _, f := range []url.Values{
		policyForm(true, "Bad_NS", "/x", ""),
		policyForm(true, "a", "no-slash", ""),
		policyForm(true, "a", "/x", "Bad_NS"),
		{"namespace": {"a", "a"}, "paths": {"/x", "/y"}, "targets": {"", ""}},
	} {
		if _, body := post(t, c, base, f); !strings.Contains(body, `role="alert"`) {
			t.Fatalf("no error shown for %v:\n%s", f, body)
		}
	}
	if p, _ := store.Get(context.Background()); p.Enabled || len(p.Namespaces) != 0 || *calls != 0 {
		t.Fatalf("policy saved: %+v, calls %d", p, *calls)
	}
}

func TestSyncPolicyConfirmation(t *testing.T) {
	base, c, store, calls := newPolicyServer(t, previewByPaths, true)

	f := policyForm(true, "team-a", "/apps", "")
	f.Set("confirm", "delete")
	if _, body := post(t, c, base, f); !strings.Contains(body, "denied: /apps") {
		t.Fatalf("first POST with confirm and no digest was not previewed:\n%s", body)
	}
	f.Del("confirm")

	_, body := post(t, c, base, f)
	digestA := digestOf(t, body)
	if !strings.Contains(body, "team-a/app: denied: /apps") || !strings.Contains(body, `name="confirm"`) {
		t.Fatalf("confirmation not requested:\n%s", body)
	}
	if p, _ := store.Get(context.Background()); p.Enabled || *calls != 0 {
		t.Fatalf("saved without confirmation: %+v", p)
	}

	f.Set("confirm", "nope")
	f.Set("digest", digestA)
	post(t, c, base, f)
	if p, _ := store.Get(context.Background()); p.Enabled {
		t.Fatal("saved with a wrong confirmation")
	}

	b := policyForm(true, "team-a", "/apps /other /more", "")
	b.Set("confirm", "delete")
	b.Set("digest", digestA)
	if _, body = post(t, c, base, b); !strings.Contains(body, "denied: /more") || digestOf(t, body) == digestA {
		t.Fatalf("edited policy not previewed again:\n%s", body)
	}
	if p, _ := store.Get(context.Background()); p.Enabled {
		t.Fatal("saved a policy that was never previewed")
	}

	f.Set("confirm", "delete")
	post(t, c, base, f)
	p, _ := store.Get(context.Background())
	if !p.Enabled || !slices.Equal(p.Namespaces["team-a"].Paths, []string{"/apps"}) || *calls != 1 {
		t.Fatalf("confirmed save: %+v, calls %d", p, *calls)
	}

	_, body = get(t, c, base+"/audit")
	if !strings.Contains(body, "<code>enable_sync_policy</code>") || !strings.Contains(body, "team-a") {
		t.Fatalf("audit page:\n%s", body)
	}
}

func TestSyncPolicyRoundTripAndOps(t *testing.T) {
	base, c, store, _ := newPolicyServer(t, nil, false)
	if _, err := store.Put(context.Background(), storage.SyncPolicy{}, storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{
		"team-a": {Paths: []string{"/a", "/b"}, TargetNamespaces: []string{"team-b"}},
	}}); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, c, base+"/sync-policy")
	for _, want := range []string{`value="team-a"`, "/a\n/b", `value="team-b"`, " checked>", "has no effect until it runs"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q:\n%s", want, body)
		}
	}

	post(t, c, base, policyForm(true, "team-a", "/a", ""))
	post(t, c, base, policyForm(false, "team-a", "/a", ""))
	_, body = get(t, c, base+"/audit")
	for _, op := range []string{"update_sync_policy", "disable_sync_policy"} {
		if !strings.Contains(body, "<code>"+op+"</code>") {
			t.Fatalf("audit lacks %s:\n%s", op, body)
		}
	}

	_, body = get(t, c, base+"/")
	if !strings.Contains(body, "SecretSync policy") {
		t.Fatalf("summary lacks the policy:\n%s", body)
	}
}

func TestSyncPolicyChangeSincePageWasReadConflicts(t *testing.T) {
	base, c, store, calls := newPolicyServer(t, nil, true)
	_, page := get(t, c, base+"/sync-policy")
	m := baseRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no base in page:\n%s", page)
	}
	other := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"other": {Paths: []string{"/o"}}}}
	if _, err := store.Put(context.Background(), storage.SyncPolicy{}, other); err != nil {
		t.Fatal(err)
	}
	before := *calls

	for name, f := range map[string]url.Values{"stale base": policyForm(true, "team-a", "/a", ""), "no base": policyForm(true, "team-a", "/a", "")} {
		if name == "stale base" {
			f.Set("base", m[1])
		} else {
			f.Set("base", "")
		}
		code, body := post(t, c, base, f)
		if code != http.StatusOK || !strings.Contains(body, "changed since it was read") || !strings.Contains(body, `value="other"`) {
			t.Fatalf("%s: %d\n%s", name, code, body)
		}
	}
	if p, _ := store.Get(context.Background()); p.Namespaces["team-a"].Paths != nil || *calls != before {
		t.Fatalf("a conflicting save changed the policy: %+v", p)
	}
	if _, audit := get(t, c, base+"/audit"); !strings.Contains(audit, "changed since it was read") {
		t.Fatalf("conflict not audited:\n%s", audit)
	}

	f := policyForm(true, "team-a", "/a", "")
	if code, body := post(t, c, base, f); code != http.StatusOK || strings.Contains(body, "changed since") {
		t.Fatalf("save on the current policy: %d\n%s", code, body)
	}
	if p, _ := store.Get(context.Background()); p.Namespaces["team-a"].Paths == nil {
		t.Fatalf("not saved: %+v", p)
	}
}

func TestSyncPolicyConfirmPageKeepsTheBase(t *testing.T) {
	base, c, store, _ := newPolicyServer(t, previewByPaths, true)
	_, page := get(t, c, base+"/sync-policy")
	m := baseRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no base in page")
	}
	if _, err := store.Put(context.Background(), storage.SyncPolicy{}, storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"other": {Paths: []string{"/o"}}}}); err != nil {
		t.Fatal(err)
	}
	f := policyForm(true, "team-a", "/a", "")
	f.Set("base", m[1])
	if _, body := post(t, c, base, f); !strings.Contains(body, "changed since it was read") {
		t.Fatalf("stale base accepted:\n%s", body)
	}

	cur, _ := store.Get(context.Background())
	f.Set("base", baseDigest(cur))
	_, body := post(t, c, base, f)
	if got := baseRe.FindStringSubmatch(body); got == nil || got[1] != baseDigest(cur) || !strings.Contains(body, `name="digest"`) {
		t.Fatalf("confirmation page lost the base:\n%s", body)
	}
}

func TestPolicyDigestIsUnambiguous(t *testing.T) {
	p := storage.SyncPolicy{Enabled: true}
	if policyDigest(p, []string{"a\nb"}) == policyDigest(p, []string{"a", "b"}) {
		t.Fatal("entries joined with a newline collide")
	}
	if policyDigest(p, nil) != policyDigest(p, []string{}) {
		t.Fatal("no list and an empty list differ")
	}
}

func TestSyncPolicyEscapesInput(t *testing.T) {
	base, c, _, _ := newPolicyServer(t, nil, true)
	_, body := post(t, c, base, policyForm(true, "<script>alert(1)</script>", "/x", ""))
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatalf("unescaped input:\n%s", body)
	}
}

func TestSyncPolicyHiddenWithoutStore(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	if code, _ := get(t, c, ts.URL+"/sync-policy"); code != http.StatusNotFound {
		t.Fatalf("GET: %d", code)
	}
	f := policyForm(true, "a", "/x", "")
	f.Set("base", "x")
	if code, _ := post(t, c, ts.URL, f); code != http.StatusNotFound {
		t.Fatalf("POST: %d", code)
	}
	if _, body := get(t, c, ts.URL+"/"); strings.Contains(body, "/sync-policy") {
		t.Fatalf("nav link shown:\n%s", body)
	}
}
