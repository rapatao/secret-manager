package controller

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/rapatao/secret-manager/api/v1alpha1"
	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
)

type failingPolicyBackend struct{ storage.Backend }

func (failingPolicyBackend) SyncPolicy(context.Context) (storage.SyncPolicy, error) {
	return storage.SyncPolicy{}, errors.New("backend down")
}

func (e *env) policy(p storage.SyncPolicy) {
	e.t.Helper()
	if e.r.Policy == nil {
		e.r.Policy = syncpolicy.New(k8sstorage.New(e.c, "secret-manager"), nil)
	}
	if _, err := e.r.Policy.Put(e.ctx, p); err != nil {
		e.t.Fatal(err)
	}
}

func allow(ns string, paths []string, targets ...string) storage.SyncPolicy {
	return storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{
		ns: {Paths: paths, TargetNamespaces: targets},
	}}
}

func notAllowed(t *testing.T, e *env, ss *v1alpha1.SecretSync) {
	t.Helper()
	c := e.ready(ss)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "NotAllowed" {
		t.Fatalf("condition %+v, want Ready=False NotAllowed", c)
	}
}

func TestPolicyPreviewListsDisallowed(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t", Namespace: "elsewhere"})
	e := newEnv(t, ss)
	for _, name := range []string{"zeta", "beta", "alpha"} {
		other := secretSync(v1alpha1.Target{Name: "t", Namespace: "elsewhere"})
		other.Name = name
		if err := e.c.Create(e.ctx, other); err != nil {
			t.Fatal(err)
		}
	}
	preview := PolicyPreview(e.c)

	got, err := preview(e.ctx, allow("app", []string{"/kubernetes"}))
	if err != nil || len(got) != 4 || !slices.IsSorted(got) || !strings.HasPrefix(got[0], "app/alpha: ") ||
		!strings.HasPrefix(got[3], "app/zeta: ") || !strings.Contains(got[0], "elsewhere") {
		t.Fatalf("preview = %v, %v", got, err)
	}
	if got, err = preview(e.ctx, allow("app", []string{"/kubernetes"}, "elsewhere")); err != nil || len(got) != 0 {
		t.Fatalf("allowed policy: %v, %v", got, err)
	}
	if got, err = preview(e.ctx, storage.SyncPolicy{}); err != nil || len(got) != 0 {
		t.Fatalf("disabled policy: %v, %v", got, err)
	}
}

func TestPolicyDisabledAllowsEverything(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t", Namespace: "elsewhere"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.policy(storage.SyncPolicy{Enabled: false})
	e.reconcile(ss)
	if _, err := e.secret("elsewhere", "t"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyUnlistedNamespaceRemovesTargetsIncludingOrphan(t *testing.T) {
	ss := secretSync(
		v1alpha1.Target{Name: "owned"},
		v1alpha1.Target{Name: "orphan", CreationPolicy: v1alpha1.CreationPolicyOrphan},
		v1alpha1.Target{Name: "t", Namespace: "other"},
	)
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "t"}, Data: map[string][]byte{"x": []byte("y")}}
	e := newEnv(t, ss, foreign)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	if _, err := e.secret("app", "orphan"); err != nil {
		t.Fatal(err)
	}

	e.policy(allow("elsewhere", []string{"/"}))
	e.events()
	e.reconcile(ss)

	for _, name := range []string{"owned", "orphan"} {
		if _, err := e.secret("app", name); err == nil {
			t.Fatalf("secret %s still exists", name)
		}
	}
	got, err := e.secret("other", "t")
	if err != nil || string(got.Data["x"]) != "y" || got.Labels[OwnerLabel] != "" {
		t.Fatalf("foreign secret touched: %v %+v", err, got)
	}
	notAllowed(t, e, ss)
	if !hasEvent(e.events(), "NotAllowed") {
		t.Fatal("no NotAllowed event")
	}
}

func hasEvent(evs []string, reason string) bool {
	for _, ev := range evs {
		if strings.Contains(ev, reason) {
			return true
		}
	}
	return false
}

func TestPolicySourceOutsidePrefixDenied(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.policy(allow("app", []string{"/other"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err == nil {
		t.Fatal("target created")
	}
	notAllowed(t, e, ss)
}

func TestPolicyRecursiveSourceUnderPrefixAllowed(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	ss.Spec.Sources = []v1alpha1.Source{{Path: "/kubernetes/app", Recursive: true}}
	e := newEnv(t, ss)
	e.set("/kubernetes/app/db", map[string]string{"A": "1"})
	e.policy(allow("app", []string{"/kubernetes"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyTargetNamespaces(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "own", Namespace: "app"}, v1alpha1.Target{Name: "t", Namespace: "other"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.policy(allow("app", []string{"/kubernetes"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "own"); err == nil {
		t.Fatal("any denied target must disallow the whole SecretSync")
	}
	notAllowed(t, e, ss)

	e.policy(allow("app", []string{"/kubernetes"}, "other"))
	e.reconcile(ss)
	for _, k := range [][2]string{{"app", "own"}, {"other", "t"}} {
		if _, err := e.secret(k[0], k[1]); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	if c := e.ready(ss); c.Status != metav1.ConditionTrue {
		t.Fatalf("condition %+v", c)
	}
}

func TestPolicyEmptyTargetNamespaceIsOwn(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.policy(allow("app", []string{"/kubernetes"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyReallowRecreatesTargets(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	e.policy(allow("elsewhere", []string{"/"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err == nil {
		t.Fatal("target kept")
	}
	e.policy(allow("app", []string{"/kubernetes"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyLoadErrorChangesNothing(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	before := e.ready(ss)

	e.r.Policy = syncpolicy.New(failingPolicyBackend{k8sstorage.New(e.c, "secret-manager")}, nil)
	_, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := e.secret("app", "t"); err != nil {
		t.Fatalf("target removed: %v", err)
	}
	if after := e.ready(ss); after.Reason != before.Reason || after.Status != before.Status {
		t.Fatalf("status changed: %+v", after)
	}
}

func TestNotifyAllEnqueuesEverySecretSync(t *testing.T) {
	a := secretSync()
	b := secretSync()
	b.Name = "second"
	b.Spec.Sources = []v1alpha1.Source{{Path: "/elsewhere"}}
	e := newEnv(t, a, b)
	e.r.Changes = NewChanges()
	e.r.Changes.NotifyAll()
	ev := <-e.r.Changes.all
	reqs := e.r.RequestsForPath(e.ctx, ev.Object)
	want := map[reconcile.Request]bool{
		{NamespacedName: client.ObjectKeyFromObject(a)}: true,
		{NamespacedName: client.ObjectKeyFromObject(b)}: true,
	}
	if len(reqs) != 2 || !want[reqs[0]] || !want[reqs[1]] {
		t.Fatalf("requests %v", reqs)
	}
}

func TestNotifyAllSurvivesFullPathQueue(t *testing.T) {
	c := NewChanges()
	for range cap(c.paths) + 10 {
		c.Notify("/a")
	}
	c.NotifyAll()
	select {
	case <-c.all:
	default:
		t.Fatal("broadcast dropped because the path queue was full")
	}
}

func TestNotifyAllCoalesces(t *testing.T) {
	c := NewChanges()
	c.NotifyAll()
	c.NotifyAll()
	<-c.all
	select {
	case <-c.all:
		t.Fatal("second broadcast queued")
	default:
	}
}

func TestFailedListRetriesBroadcast(t *testing.T) {
	old := policyRetry
	policyRetry = 10 * time.Millisecond
	t.Cleanup(func() { policyRetry = old })

	e := newEnvWith(t, interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
		return errors.New("list failed")
	}})
	e.r.Changes = NewChanges()
	if reqs := e.r.RequestsForPath(e.ctx, ""); len(reqs) != 0 {
		t.Fatalf("requests %v", reqs)
	}
	select {
	case <-e.r.Changes.all:
	case <-time.After(5 * time.Second):
		t.Fatal("no retry broadcast")
	}
}

func TestRefreshIntervalIsClamped(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	ss.Spec.RefreshInterval = &metav1.Duration{Duration: 48 * time.Hour}
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	if res := e.reconcile(ss); res.RequeueAfter != time.Hour {
		t.Fatalf("RequeueAfter %v", res.RequeueAfter)
	}

	e.policy(storage.SyncPolicy{Enabled: true})
	if res := e.reconcile(ss); res.RequeueAfter != time.Hour {
		t.Fatalf("denied RequeueAfter %v", res.RequeueAfter)
	}
	notAllowed(t, e, ss)
}

func TestCRDLimitsRefreshInterval(t *testing.T) {
	b, err := os.ReadFile("../../charts/secret-manager/crds/secretmanager.rapatao.com_secretsyncs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, "x-kubernetes-validations") || !strings.Contains(s, "duration(self) <= duration('1h')") {
		t.Fatal("CRD lacks the refreshInterval rule")
	}
}

func TestPolicyDeniedKeepsSecretWithoutOwnerAnnotation(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	owned, err := e.secret("app", "t")
	if err != nil {
		t.Fatal(err)
	}
	labelOnly := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "other", Name: "label-only", Labels: map[string]string{OwnerLabel: owned.Labels[OwnerLabel]},
	}}
	if err := e.c.Create(e.ctx, labelOnly); err != nil {
		t.Fatal(err)
	}
	e.policy(allow("elsewhere", []string{"/"}))
	e.reconcile(ss)
	if _, err := e.secret("app", "t"); err == nil {
		t.Fatal("owned secret kept")
	}
	if _, err := e.secret("other", "label-only"); err != nil {
		t.Fatalf("label-only secret deleted: %v", err)
	}
}

func TestPolicyDeniedRemovesSecretOfRemovedTargetAndEmitsReleased(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t", Namespace: "old"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	if _, err := e.secret("old", "t"); err != nil {
		t.Fatal(err)
	}
	var cur v1alpha1.SecretSync
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Targets = []v1alpha1.Target{{Name: "t"}}
	if err := e.c.Update(e.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	e.policy(allow("elsewhere", []string{"/"}))
	e.events()
	e.reconcile(ss)
	if _, err := e.secret("old", "t"); err == nil {
		t.Fatal("secret of removed target kept")
	}
	if !hasEvent(e.events(), "Released") {
		t.Fatal("no Released event")
	}
}

func TestPolicyDeniedDeleteFailureStillAttemptsOthers(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "a"}, v1alpha1.Target{Name: "b"}, v1alpha1.Target{Name: "c"})
	e := newEnvWith(t, interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if obj.GetName() == "a" {
			return errors.New("boom")
		}
		return c.Delete(ctx, obj, opts...)
	}}, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	e.policy(allow("elsewhere", []string{"/"}))
	_, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)})
	if err == nil || !strings.Contains(err.Error(), "app/a") {
		t.Fatalf("error %v", err)
	}
	if _, err := e.secret("app", "a"); err != nil {
		t.Fatalf("a: %v", err)
	}
	for _, n := range []string{"b", "c"} {
		if _, err := e.secret("app", n); err == nil {
			t.Fatalf("%s kept", n)
		}
	}
	notAllowed(t, e, ss)
}

func TestPolicyDeletingDeniedSecretSyncFollowsCreationPolicy(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "owned"}, v1alpha1.Target{Name: "orphan", CreationPolicy: v1alpha1.CreationPolicyOrphan})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	e.policy(allow("elsewhere", []string{"/"}))
	if err := e.c.Delete(e.ctx, ss); err != nil {
		t.Fatal(err)
	}
	if _, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.secret("app", "owned"); err == nil {
		t.Fatal("owned target kept")
	}
	kept, err := e.secret("app", "orphan")
	if err != nil {
		t.Fatalf("orphan target deleted: %v", err)
	}
	if kept.Labels[OwnerLabel] != "" {
		t.Fatalf("orphan still owned: %v", kept.Labels)
	}
}
