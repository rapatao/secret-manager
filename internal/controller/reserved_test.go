package controller

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rapatao/secret-manager/api/v1alpha1"
)

func TestReservedMetadataIsRejected(t *testing.T) {
	for name, meta := range map[string]v1alpha1.TargetMetadata{
		"label":      {Labels: map[string]string{"secretmanager.rapatao.com/store": "true"}},
		"annotation": {Annotations: map[string]string{"secretmanager.rapatao.com/path": "/x"}},
	} {
		t.Run(name, func(t *testing.T) {
			ss := secretSync(v1alpha1.Target{Name: "t", Metadata: meta})
			e := newEnv(t, ss)
			e.set("/kubernetes", map[string]string{"A": "1"})
			e.reconcile(ss)

			if _, err := e.secret("app", "t"); !apierrors.IsNotFound(err) {
				t.Fatalf("Secret created: %v", err)
			}
			c := e.ready(ss)
			if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "SyncFailed" || !strings.Contains(c.Message, "secretmanager.rapatao.com/") {
				t.Fatalf("ready condition %+v", c)
			}
			if !hasEvent(e.events(), "SyncFailed") {
				t.Fatal("no Warning event")
			}
		})
	}
}

func TestReservedMetadataKeysAreListedSorted(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t", Metadata: v1alpha1.TargetMetadata{
		Labels:      map[string]string{"secretmanager.rapatao.com/b": "1", "secretmanager.rapatao.com/a": "1", "ok": "1"},
		Annotations: map[string]string{"secretmanager.rapatao.com/c": "1"},
	}})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	msg := e.ready(ss).Message
	a, b, c := strings.Index(msg, "rapatao.com/a"), strings.Index(msg, "rapatao.com/b"), strings.Index(msg, "rapatao.com/c")
	if a < 0 || a > b || b > c || strings.Contains(msg, "ok") {
		t.Fatalf("message %q", msg)
	}
}

func TestReservedNamesInStorageNamespace(t *testing.T) {
	reserved := []string{"sm", "sm-tokens", "sm-audit", "sm-sync-policy", "sm.a", "smh.a.1"}

	ss := secretSync()
	for _, n := range reserved {
		ss.Spec.Targets = append(ss.Spec.Targets, v1alpha1.Target{Name: n, Namespace: "sm-ns"})
	}
	ss.Spec.Targets = append(ss.Spec.Targets, v1alpha1.Target{Name: "sm-foo", Namespace: "sm-ns"})
	e := newEnv(t, ss)
	e.r.StorageNamespace = "sm-ns"
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	for _, n := range reserved {
		if _, err := e.secret("sm-ns", n); !apierrors.IsNotFound(err) {
			t.Errorf("%s created in the storage namespace: %v", n, err)
		}
	}
	if _, err := e.secret("sm-ns", "sm-foo"); err != nil {
		t.Errorf("sm-foo not synced: %v", err)
	}
	c := e.ready(ss)
	if c == nil || c.Reason != "SyncFailed" || !strings.Contains(c.Message, "reserved for the server's storage") {
		t.Fatalf("ready condition %+v", c)
	}
}

func TestReservedNamesElsewhereSync(t *testing.T) {
	for name, storageNS := range map[string]string{"other namespace": "sm-ns", "no storage namespace": ""} {
		t.Run(name, func(t *testing.T) {
			ns := "elsewhere"
			if storageNS == "" {
				ns = "sm-ns"
			}
			ss := secretSync()
			for _, n := range []string{"sm-sync-policy", "sm.a", "smh.a.1"} {
				ss.Spec.Targets = append(ss.Spec.Targets, v1alpha1.Target{Name: n, Namespace: ns})
			}
			e := newEnv(t, ss)
			e.r.StorageNamespace = storageNS
			e.set("/kubernetes", map[string]string{"A": "1"})
			e.reconcile(ss)
			for _, n := range []string{"sm-sync-policy", "sm.a", "smh.a.1"} {
				if _, err := e.secret(ns, n); err != nil {
					t.Errorf("%s not synced: %v", n, err)
				}
			}
			if c := e.ready(ss); c == nil || c.Status != metav1.ConditionTrue {
				t.Fatalf("ready condition %+v", c)
			}
		})
	}
}

func TestRejectedTargetIsNotReleased(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "sm.a", Namespace: "sm-ns"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	e.r.StorageNamespace = "sm-ns"
	e.reconcile(ss)
	if _, err := e.secret("sm-ns", "sm.a"); err != nil {
		t.Fatalf("existing target released after becoming reserved: %v", err)
	}
	if c := e.ready(ss); c == nil || c.Reason != "SyncFailed" {
		t.Fatalf("ready condition %+v", c)
	}
}

func TestOrphanReleaseDropsEveryReservedKey(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "kept", CreationPolicy: v1alpha1.CreationPolicyOrphan})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	s, err := e.secret("app", "kept")
	if err != nil {
		t.Fatal(err)
	}
	s.Labels["secretmanager.rapatao.com/store"] = "true"
	s.Labels["team"] = "x"
	s.Annotations["secretmanager.rapatao.com/path"] = "/x"
	s.Annotations["note"] = "y"
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}

	var cur v1alpha1.SecretSync
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Delete(e.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ss)

	if s, err = e.secret("app", "kept"); err != nil {
		t.Fatalf("Orphan target deleted: %v", err)
	}
	for _, m := range []map[string]string{s.Labels, s.Annotations} {
		for k := range m {
			if strings.HasPrefix(k, "secretmanager.rapatao.com/") {
				t.Fatalf("reserved key %s kept: %v %v", k, s.Labels, s.Annotations)
			}
		}
	}
	if s.Labels["team"] != "x" || s.Annotations["note"] != "y" {
		t.Fatalf("other metadata lost: %v %v", s.Labels, s.Annotations)
	}
}

func TestSyncCleansForgedReservedMetadataOfOwnedTarget(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	e := newEnv(t, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	s, err := e.secret("app", "t")
	if err != nil {
		t.Fatal(err)
	}
	s.Labels["secretmanager.rapatao.com/store"] = "true"
	s.Annotations["secretmanager.rapatao.com/path"] = "/x"
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ss)

	s, _ = e.secret("app", "t")
	if _, ok := s.Labels["secretmanager.rapatao.com/store"]; ok {
		t.Fatalf("forged label kept: %v", s.Labels)
	}
	if _, ok := s.Annotations["secretmanager.rapatao.com/path"]; ok {
		t.Fatalf("forged annotation kept: %v", s.Annotations)
	}
}

func orphanSecret(ns, name string, annotated bool) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name,
		Labels: map[string]string{
			OwnerLabel:  hashOwner("app/sync"),
			PolicyLabel: string(v1alpha1.CreationPolicyOrphan),
		},
	}}
	if annotated {
		s.Annotations = map[string]string{OwnerAnnotation: "app/sync"}
	}
	return s
}

func TestReleaseOrphanByNameAndNamespace(t *testing.T) {
	cases := []struct {
		name, storageNS, ns, secret string
		deleted                     bool
	}{
		{"reserved in storage namespace", "sm-ns", "sm-ns", "sm-sync-policy", true},
		{"reserved path name", "sm-ns", "sm-ns", "sm.a", true},
		{"not reserved in storage namespace", "sm-ns", "sm-ns", "sm-foo", false},
		{"reserved in another namespace", "sm-ns", "elsewhere", "sm-sync-policy", false},
		{"no storage namespace", "", "sm-ns", "sm-sync-policy", false},
	}
	for _, c := range cases {
		for _, how := range []string{"leaves targets", "SecretSync deleted"} {
			t.Run(c.name+"/"+how, func(t *testing.T) {
				ss := secretSync(v1alpha1.Target{Name: "other"})
				e := newEnv(t, ss, orphanSecret(c.ns, c.secret, true))
				e.r.StorageNamespace = c.storageNS
				e.set("/kubernetes", map[string]string{"A": "1"})
				e.reconcile(ss)
				if how == "SecretSync deleted" {
					var cur v1alpha1.SecretSync
					if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); err != nil {
						t.Fatal(err)
					}
					if err := e.c.Delete(e.ctx, &cur); err != nil {
						t.Fatal(err)
					}
					e.reconcile(ss)
				}

				s, err := e.secret(c.ns, c.secret)
				released := hasEvent(e.events(), "Released")
				if c.deleted {
					if !apierrors.IsNotFound(err) || !released {
						t.Fatalf("not deleted with a Released event: %v, event %v", err, released)
					}
					return
				}
				if err != nil || released {
					t.Fatalf("detached Secret: %v, event %v", err, released)
				}
				if _, ok := s.Labels[OwnerLabel]; ok {
					t.Fatalf("still owned: %v", s.Labels)
				}
			})
		}
	}
}

func TestReleaseSkipsSecretWithoutOwnerAnnotation(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "other"})
	e := newEnv(t, ss, orphanSecret("app", "unannotated", false))
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	s, err := e.secret("app", "unannotated")
	if err != nil {
		t.Fatalf("Secret deleted: %v", err)
	}
	if _, ok := s.Labels[OwnerLabel]; !ok {
		t.Fatalf("Secret detached: %v", s.Labels)
	}
}

func deleteUID(opts []client.DeleteOption) *types.UID {
	var o client.DeleteOptions
	o.ApplyOptions(opts)
	if o.Preconditions == nil {
		return nil
	}
	return o.Preconditions.UID
}

func TestReleaseDeletesWithUIDPrecondition(t *testing.T) {
	for name, force := range map[string]bool{"non-force": false, "force": true} {
		t.Run(name, func(t *testing.T) {
			ss := secretSync(v1alpha1.Target{Name: "t"})
			var seen []*types.UID
			conflict := false
			e := newEnvWith(t, interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.Secret); !ok {
					return c.Delete(ctx, obj, opts...)
				}
				seen = append(seen, deleteUID(opts))
				if conflict {
					return apierrors.NewConflict(corev1.Resource("secrets"), obj.GetName(), errors.New("uid mismatch"))
				}
				return c.Delete(ctx, obj, opts...)
			}}, ss)
			e.set("/kubernetes", map[string]string{"A": "1"})
			e.reconcile(ss)
			s, err := e.secret("app", "t")
			if err != nil {
				t.Fatal(err)
			}
			s.UID = "uid-1"
			if err := e.c.Update(e.ctx, s); err != nil {
				t.Fatal(err)
			}

			if force {
				e.policy(allow("elsewhere", []string{"/"}))
			} else {
				var cur v1alpha1.SecretSync
				if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ss), &cur); err != nil {
					t.Fatal(err)
				}
				cur.Spec.Targets = []v1alpha1.Target{{Name: "other"}}
				if err := e.c.Update(e.ctx, &cur); err != nil {
					t.Fatal(err)
				}
			}
			conflict = true
			_, err = e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)})
			msg := ""
			if err != nil {
				msg = err.Error()
			} else if c := e.ready(ss); c != nil {
				msg = c.Message
			}
			if !strings.Contains(msg, "uid mismatch") {
				t.Fatalf("conflict not reported: err %v, message %q", err, msg)
			}
			if _, err := e.secret("app", "t"); err != nil {
				t.Fatalf("Secret deleted despite the conflict: %v", err)
			}
			if len(seen) == 0 || seen[0] == nil || *seen[0] != "uid-1" {
				t.Fatalf("UID precondition %v", seen)
			}
		})
	}
}

func TestReservedOrphanNotFoundEmitsNoEvent(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "other"})
	e := newEnvWith(t, interceptor.Funcs{Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
		return apierrors.NewNotFound(corev1.Resource("secrets"), obj.GetName())
	}}, ss, orphanSecret("sm-ns", "sm-tokens", true))
	e.r.StorageNamespace = "sm-ns"
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)
	if hasEvent(e.events(), "Released") {
		t.Fatal("Released event for a Secret that was already gone")
	}
	if c := e.ready(ss); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("release failed on a Secret that was already gone: %+v", c)
	}
}

func TestTargetTypeAllowList(t *testing.T) {
	for typ, ok := range map[corev1.SecretType]bool{
		"":                                   true,
		corev1.SecretTypeOpaque:              true,
		corev1.SecretTypeTLS:                 true,
		corev1.SecretTypeDockerConfigJson:    true,
		corev1.SecretTypeBasicAuth:           true,
		corev1.SecretTypeSSHAuth:             true,
		corev1.SecretTypeServiceAccountToken: false,
		corev1.SecretTypeDockercfg:           false,
		"example.com/custom":                 false,
	} {
		t.Run(string(typ), func(t *testing.T) {
			ss := secretSync(v1alpha1.Target{Name: "t", Type: typ})
			e := newEnv(t, ss)
			e.set("/kubernetes", map[string]string{"A": "1"})
			e.reconcile(ss)

			s, err := e.secret("app", "t")
			c := e.ready(ss)
			if ok {
				if err != nil || c == nil || c.Status != metav1.ConditionTrue {
					t.Fatalf("not synced: %v, %+v", err, c)
				}
				return
			}
			if !apierrors.IsNotFound(err) {
				t.Fatalf("Secret of type %s created: %v", s.Type, err)
			}
			if c == nil || c.Reason != "SyncFailed" || !strings.Contains(c.Message, string(typ)) || !strings.Contains(c.Message, "kubernetes.io/tls") {
				t.Fatalf("ready condition %+v", c)
			}
			if !hasEvent(e.events(), "SyncFailed") {
				t.Fatal("no Warning event")
			}
		})
	}
}

func TestCRDListsTheAllowedTargetTypes(t *testing.T) {
	f, err := os.Open("../../charts/secret-manager/crds/secretmanager.rapatao.com_secretsyncs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var crd map[string]any
	if err := yaml.NewYAMLOrJSONDecoder(f, 4096).Decode(&crd); err != nil {
		t.Fatal(err)
	}
	typ, found, err := unstructured.NestedFieldNoCopy(crd, "spec", "versions")
	if err != nil || !found {
		t.Fatalf("versions: %v, %v", found, err)
	}
	schema := typ.([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
	field, found, err := unstructured.NestedFieldNoCopy(schema, "properties", "spec", "properties", "targets", "items", "properties", "type", "enum")
	if err != nil || !found {
		t.Fatalf("target type enum: %v, %v", found, err)
	}
	want := []any{""}
	for _, a := range allowedTypes {
		want = append(want, string(a))
	}
	if !slices.Equal(field.([]any), want) {
		t.Fatalf("CRD enum %v, want %v", field, want)
	}
}

func TestForcedReleaseIgnoresNotFound(t *testing.T) {
	ss := secretSync(v1alpha1.Target{Name: "t"})
	gone := false
	e := newEnvWith(t, interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if _, ok := obj.(*corev1.Secret); ok && gone {
			return apierrors.NewNotFound(corev1.Resource("secrets"), obj.GetName())
		}
		return c.Delete(ctx, obj, opts...)
	}}, ss)
	e.set("/kubernetes", map[string]string{"A": "1"})
	e.reconcile(ss)

	gone = true
	e.policy(allow("elsewhere", []string{"/"}))
	e.events()
	if _, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ss)}); err != nil {
		t.Fatal(err)
	}
	if hasEvent(e.events(), "Released") {
		t.Fatal("Released event for a Secret that was already gone")
	}
}
