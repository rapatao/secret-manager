package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/rapatao/secret-manager/api/v1alpha1"
	"github.com/rapatao/secret-manager/internal/reload"
	"github.com/rapatao/secret-manager/internal/secrets"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

type env struct {
	t   *testing.T
	ctx context.Context
	c   client.Client
	svc *secrets.Service
	rec *events.FakeRecorder
	r   *SecretSyncReconciler
}

func newEnv(t *testing.T, objs ...client.Object) *env {
	t.Helper()
	return newEnvWith(t, interceptor.Funcs{}, objs...)
}

func newEnvWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *env {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.SecretSync{}).
		WithInterceptorFuncs(funcs).
		Build()
	svc := secrets.New(k8sstorage.New(c, "secret-manager"), nil)
	rec := events.NewFakeRecorder(100)
	return &env{t: t, ctx: context.Background(), c: c, svc: svc, rec: rec, r: &SecretSyncReconciler{Client: c, Secrets: svc, Recorder: rec}}
}

func (e *env) set(path string, kv map[string]string) {
	e.t.Helper()
	if err := e.svc.SetKeys(e.ctx, path, kv); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) reconcile(ss *v1alpha1.SecretSync) ctrl.Result {
	e.t.Helper()
	var res ctrl.Result
	for range 3 {
		var err error
		res, err = e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)})
		if err != nil {
			e.t.Fatalf("reconcile: %v", err)
		}
		if res.RequeueAfter > 0 {
			break
		}
	}
	return res
}

// events drains and returns the recorded events.
func (e *env) events() []string {
	var out []string
	for {
		select {
		case ev := <-e.rec.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func (e *env) secret(ns, name string) (*corev1.Secret, error) {
	var s corev1.Secret
	err := e.c.Get(e.ctx, client.ObjectKey{Namespace: ns, Name: name}, &s)
	return &s, err
}

func (e *env) ready(ss *v1alpha1.SecretSync) *metav1.Condition {
	e.t.Helper()
	var got v1alpha1.SecretSync
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &got); err != nil {
		e.t.Fatal(err)
	}
	return meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady)
}

func secretSync(targets ...v1alpha1.Target) *v1alpha1.SecretSync {
	return &v1alpha1.SecretSync{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "sync"},
		Spec: v1alpha1.SecretSyncSpec{
			Sources: []v1alpha1.Source{{Path: "/kubernetes"}},
			Targets: targets,
		},
	}
}

func TestSyncCreatesTargets(t *testing.T) {
	ss := secretSync(
		v1alpha1.Target{Name: "plain"},
		v1alpha1.Target{
			Name:      "repo-creds",
			Namespace: "argo",
			Metadata:  v1alpha1.TargetMetadata{Labels: map[string]string{"argocd.argoproj.io/secret-type": "repository"}},
			Template:  &v1alpha1.Template{Data: map[string]string{"username": "{{ .USER }}"}},
		},
	)
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"USER": "bob", "PASS": "x"})

	res := e.reconcile(ss)
	if res.RequeueAfter != defaultRefresh {
		t.Fatalf("requeue %v, want %v", res.RequeueAfter, defaultRefresh)
	}

	plain, err := e.secret("app", "plain")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain.Data["USER"]) != "bob" || string(plain.Data["PASS"]) != "x" {
		t.Fatalf("plain data %v", plain.Data)
	}
	if plain.Type != corev1.SecretTypeOpaque {
		t.Fatalf("type %s", plain.Type)
	}

	creds, err := e.secret("argo", "repo-creds")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds.Data) != 1 || string(creds.Data["username"]) != "bob" {
		t.Fatalf("templated data %v", creds.Data)
	}
	if creds.Labels["argocd.argoproj.io/secret-type"] != "repository" {
		t.Fatalf("labels %v", creds.Labels)
	}
	if creds.Annotations[OwnerAnnotation] != "app/sync" {
		t.Fatalf("owner annotation %v", creds.Annotations)
	}

	if c := e.ready(ss); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("ready condition %+v", c)
	}
}

func TestSyncUpdatesAndRestartsDeployments(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "web", Annotations: map[string]string{reload.Annotation: "true"},
	}}
	d.Spec.Template.Spec.Containers = []corev1.Container{{Name: "web", EnvFrom: []corev1.EnvFromSource{{
		SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}},
	}}}}
	e := newEnv(t, ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	e.set("/kubernetes", map[string]string{"A": "2"})
	e.reconcile(ss)

	s, err := e.secret("app", "creds")
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Data["A"]) != "2" {
		t.Fatalf("data not updated: %v", s.Data)
	}
	var got appsv1.Deployment
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(d), &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations[reload.HashAnnotation] != s.Annotations[HashAnnotation] {
		t.Fatalf("deployment not restarted: %v", got.Spec.Template.Annotations)
	}
}

func reloadDeployment(name string, secretNames ...string) *appsv1.Deployment {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: name, Annotations: map[string]string{reload.Annotation: "true"},
	}}
	c := corev1.Container{Name: "web"}
	for _, n := range secretNames {
		c.EnvFrom = append(c.EnvFrom, corev1.EnvFromSource{
			SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: n}},
		})
	}
	d.Spec.Template.Spec.Containers = []corev1.Container{c}
	return d
}

func TestSyncRetriesFailedRestart(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	d := reloadDeployment("web", "creds")
	failFirst := true
	e := newEnvWith(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*appsv1.Deployment); ok && failFirst {
			failFirst = false
			return errors.New("boom")
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	before, err := e.secret("app", "creds")
	if err != nil {
		t.Fatal(err)
	}

	e.set("/kubernetes", map[string]string{"A": "2"})
	if _, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)}); err != nil {
		t.Fatal(err)
	}
	if c := e.ready(ss); c == nil || c.Status != metav1.ConditionFalse || c.Reason != "SyncFailed" {
		t.Fatalf("ready condition %+v", c)
	}
	s, err := e.secret("app", "creds")
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Data["A"]) != "2" {
		t.Fatalf("data not updated: %v", s.Data)
	}
	if s.Annotations[HashAnnotation] != before.Annotations[HashAnnotation] {
		t.Fatalf("hash advanced after failed restart: %v", s.Annotations)
	}

	e.reconcile(ss)
	s, err = e.secret("app", "creds")
	if err != nil {
		t.Fatal(err)
	}
	if s.Annotations[HashAnnotation] == before.Annotations[HashAnnotation] {
		t.Fatal("hash not advanced after retry")
	}
	var got appsv1.Deployment
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(d), &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations[reload.HashAnnotation] != s.Annotations[HashAnnotation] {
		t.Fatalf("deployment not restarted: %v", got.Spec.Template.Annotations)
	}
	if c := e.ready(ss); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("ready condition %+v", c)
	}
}

func deploymentPatchCounter(count *int, failFirst bool) interceptor.Funcs {
	return interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*appsv1.Deployment); ok {
			*count++
			if failFirst && *count == 1 {
				return errors.New("boom")
			}
		}
		return c.Patch(ctx, obj, p, opts...)
	}}
}

func TestSyncRevertAfterFailedRestartRestartsWorkload(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	d := reloadDeployment("web", "creds")
	patches := 0
	e := newEnvWith(t, deploymentPatchCounter(&patches, true), ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	orig, err := e.secret("app", "creds")
	if err != nil {
		t.Fatal(err)
	}

	e.set("/kubernetes", map[string]string{"A": "2"})
	if _, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)}); err != nil {
		t.Fatal(err)
	}
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	e.reconcile(ss)

	var got appsv1.Deployment
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(d), &got); err != nil {
		t.Fatal(err)
	}
	if want := orig.Annotations[HashAnnotation]; got.Spec.Template.Annotations[reload.HashAnnotation] != want {
		t.Fatalf("deployment hash %v, want %s", got.Spec.Template.Annotations, want)
	}
	if patches != 2 {
		t.Fatalf("deployment patched %d times, want 2 (failed + revert)", patches)
	}
}

func TestSyncChangeOfOneSecretRestartsSharedWorkloadOnce(t *testing.T) {
	ss := secretSync(
		v1alpha1.Target{Name: "one", Template: &v1alpha1.Template{Data: map[string]string{"K": "{{ .A }}"}}},
		v1alpha1.Target{Name: "two", Template: &v1alpha1.Template{Data: map[string]string{"K": "const"}}},
	)
	d := reloadDeployment("web", "one", "two")
	patches := 0
	e := newEnvWith(t, deploymentPatchCounter(&patches, false), ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	e.set("/kubernetes", map[string]string{"A": "2"})
	e.reconcile(ss)
	if patches != 1 {
		t.Fatalf("deployment patched %d times, want 1", patches)
	}
	e.reconcile(ss)
	e.reconcile(ss)
	if patches != 1 {
		t.Fatalf("deployment patched %d times after resyncs, want 1", patches)
	}
}

func TestSyncUnchangedDoesNotRestartSharedWorkload(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "one"}, v1alpha1.Target{Name: "two", Template: &v1alpha1.Template{Data: map[string]string{"B": "{{ .A }}x"}}})
	d := reloadDeployment("web", "one", "two")
	patches := 0
	e := newEnvWith(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*appsv1.Deployment); ok {
			patches++
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	for range 3 {
		e.reconcile(ss)
	}
	if patches != 0 {
		t.Fatalf("deployment patched %d times without a change", patches)
	}
}

func TestSyncRepairsDrift(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	s, _ := e.secret("app", "creds")
	s.Data["A"] = []byte("tampered")
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ss)

	s, _ = e.secret("app", "creds")
	if string(s.Data["A"]) != "1" {
		t.Fatalf("drift not repaired: %v", s.Data)
	}
}

func TestSyncRefusesForeignSecret(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "taken"})
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "taken"},
		Data:       map[string][]byte{"keep": []byte("me")},
	}
	e := newEnv(t, ss, foreign)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	s, _ := e.secret("app", "taken")
	if string(s.Data["keep"]) != "me" || len(s.Data) != 1 {
		t.Fatalf("foreign secret modified: %v", s.Data)
	}
	c := e.ready(ss)
	if c == nil || c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, "not managed") {
		t.Fatalf("ready condition %+v", c)
	}
}

func TestSyncMissingSource(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	e := newEnv(t, ss)
	e.reconcile(ss)

	c := e.ready(ss)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "SourceError" {
		t.Fatalf("ready condition %+v", c)
	}
}

func TestRemovedTargetsAndDeletion(t *testing.T) {
	ss := secretSync(
		v1alpha1.Target{Name: "owned"},
		v1alpha1.Target{Name: "kept", Namespace: "other", CreationPolicy: v1alpha1.CreationPolicyOrphan},
		v1alpha1.Target{Name: "dropped"},
	)
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	var cur v1alpha1.SecretSync
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Targets = cur.Spec.Targets[:2]
	if err := e.c.Update(e.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ss)
	if _, err := e.secret("app", "dropped"); !apierrors.IsNotFound(err) {
		t.Fatalf("removed Owner target still exists: %v", err)
	}

	if err := e.c.Delete(e.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ss)

	if _, err := e.secret("app", "owned"); !apierrors.IsNotFound(err) {
		t.Fatalf("Owner target not deleted: %v", err)
	}
	kept, err := e.secret("other", "kept")
	if err != nil {
		t.Fatalf("Orphan target deleted: %v", err)
	}
	if _, ok := kept.Labels[OwnerLabel]; ok {
		t.Fatalf("Orphan target still labeled as owned: %v", kept.Labels)
	}
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); !apierrors.IsNotFound(err) {
		t.Fatalf("SecretSync not removed after finalizer: %v", err)
	}
}

func TestRequestsForPath(t *testing.T) {
	mk := func(name, path string, recursive bool) *v1alpha1.SecretSync {
		return &v1alpha1.SecretSync{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec:       v1alpha1.SecretSyncSpec{Sources: []v1alpha1.Source{{Path: path, Recursive: recursive}}},
		}
	}
	e := newEnv(t,
		mk("exact", "/kubernetes/", false),
		mk("recursive", "/kubernetes", true),
		mk("nested-only", "/kubernetes/db", false),
		mk("other", "/tools", true),
	)

	names := func(path string) []string {
		var out []string
		for _, r := range e.r.RequestsForPath(e.ctx, path) {
			out = append(out, r.Name)
		}
		return out
	}
	if got := strings.Join(names("/kubernetes"), ","); got != "exact,recursive" {
		t.Fatalf("/kubernetes -> %s", got)
	}
	if got := strings.Join(names("/kubernetes/db"), ","); got != "nested-only,recursive" {
		t.Fatalf("/kubernetes/db -> %s", got)
	}
}

func TestChangesNotifyNeverBlocks(t *testing.T) {
	c := Changes{paths: make(chan event.TypedGenericEvent[string], 1)}
	c.Notify("/a")
	c.Notify("/b")
	if got := (<-c.paths).Object; got != "/a" {
		t.Fatalf("got %s", got)
	}
}

func TestSyncEventsAndRestartMetric(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "creds"})
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "web", Annotations: map[string]string{reload.Annotation: "true"},
	}}
	d.Spec.Template.Spec.Containers = []corev1.Container{{Name: "web", EnvFrom: []corev1.EnvFromSource{{
		SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "creds"}},
	}}}}
	e := newEnv(t, ss, d)
	e.set("/kubernetes", map[string]string{"A": "1"})

	e.reconcile(ss)
	if got := e.events(); len(got) != 1 || got[0] != "Normal Synced Created Secret app/creds" {
		t.Fatalf("create events %q", got)
	}

	e.reconcile(ss)
	if got := e.events(); len(got) != 0 {
		t.Fatalf("unchanged resync emitted %q", got)
	}

	restarts := testutil.ToFloat64(workloadRestarts.WithLabelValues("Deployment"))
	e.set("/kubernetes", map[string]string{"A": "2"})
	e.reconcile(ss)
	want := []string{
		"Normal Synced Updated Secret app/creds",
		"Normal WorkloadsRestarted Restarted Deployment/web in app for Secret creds",
	}
	if got := e.events(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("update events %q, want %q", got, want)
	}
	if got := testutil.ToFloat64(workloadRestarts.WithLabelValues("Deployment")) - restarts; got != 1 {
		t.Fatalf("restarts metric grew by %v, want 1", got)
	}
}

func TestSyncFailureWarnsOnceAndCounts(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "taken"})
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "taken"}}
	e := newEnv(t, ss, foreign)
	e.set("/kubernetes", map[string]string{"A": "1"})
	failures := testutil.ToFloat64(syncFailures.WithLabelValues("SyncFailed"))

	e.reconcile(ss)
	e.reconcile(ss)

	got := e.events()
	if len(got) != 1 || !strings.HasPrefix(got[0], "Warning SyncFailed app/taken: secret exists and is not managed") {
		t.Fatalf("events %q", got)
	}
	if n := testutil.ToFloat64(syncFailures.WithLabelValues("SyncFailed")) - failures; n != 2 {
		t.Fatalf("failures metric grew by %v, want 2", n)
	}
}
