package controller

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
	r   *SecretSyncReconciler
}

func newEnv(t *testing.T, objs ...client.Object) *env {
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
		Build()
	svc := secrets.New(k8sstorage.New(c, "secret-manager"), nil)
	return &env{t: t, ctx: context.Background(), c: c, svc: svc, r: &SecretSyncReconciler{Client: c, Secrets: svc}}
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
	c := make(Changes, 1)
	c.Notify("/a")
	c.Notify("/b")
	if got := (<-c).Object; got != "/a" {
		t.Fatalf("got %s", got)
	}
}
