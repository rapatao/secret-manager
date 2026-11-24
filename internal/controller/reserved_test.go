package controller

import (
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
