package reload

import (
	"context"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReferences(t *testing.T) {
	ref := corev1.LocalObjectReference{Name: "s"}
	cases := map[string]corev1.PodSpec{
		"envFrom": {Containers: []corev1.Container{{EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: ref}}}}}},
		"env": {Containers: []corev1.Container{{Env: []corev1.EnvVar{{Name: "X", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: ref, Key: "k"},
		}}}}}},
		"init container": {InitContainers: []corev1.Container{{EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: ref}}}}}},
		"volume":         {Volumes: []corev1.Volume{{VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "s"}}}}},
		"projected": {Volumes: []corev1.Volume{{VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: ref}}},
		}}}}},
	}
	for name, spec := range cases {
		if !References(&spec, "s") {
			t.Errorf("%s: want reference to s", name)
		}
		if References(&spec, "other") {
			t.Errorf("%s: unexpected reference to other", name)
		}
	}
}

func secretVolume(secret string) corev1.PodTemplateSpec {
	var t corev1.PodTemplateSpec
	t.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}}}}
	return t
}

func meta(name string, annotated bool) metav1.ObjectMeta {
	m := metav1.ObjectMeta{Namespace: "app", Name: name}
	if annotated {
		m.Annotations = map[string]string{Annotation: "true"}
	}
	return m
}

func TestWorkloads(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithObjects(
		&appsv1.Deployment{ObjectMeta: meta("annotated", true), Spec: appsv1.DeploymentSpec{Template: secretVolume("creds")}},
		&appsv1.Deployment{ObjectMeta: meta("not-annotated", false), Spec: appsv1.DeploymentSpec{Template: secretVolume("creds")}},
		&appsv1.Deployment{ObjectMeta: meta("other-secret", true), Spec: appsv1.DeploymentSpec{Template: secretVolume("other")}},
		&appsv1.StatefulSet{ObjectMeta: meta("db", true), Spec: appsv1.StatefulSetSpec{Template: secretVolume("creds")}},
		&appsv1.DaemonSet{ObjectMeta: meta("agent", true), Spec: appsv1.DaemonSetSpec{Template: secretVolume("creds")}},
	).Build()

	got, err := Workloads(ctx, c, "app", "creds", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Deployment/annotated", "StatefulSet/db", "DaemonSet/agent"}; !slices.Equal(got, want) {
		t.Fatalf("restarted %v, want %v", got, want)
	}

	var d appsv1.Deployment
	if err := c.Get(ctx, client.ObjectKey{Namespace: "app", Name: "annotated"}, &d); err != nil {
		t.Fatal(err)
	}
	var s appsv1.StatefulSet
	if err := c.Get(ctx, client.ObjectKey{Namespace: "app", Name: "db"}, &s); err != nil {
		t.Fatal(err)
	}
	var ds appsv1.DaemonSet
	if err := c.Get(ctx, client.ObjectKey{Namespace: "app", Name: "agent"}, &ds); err != nil {
		t.Fatal(err)
	}
	for kind, a := range map[string]map[string]string{
		"Deployment": d.Spec.Template.Annotations, "StatefulSet": s.Spec.Template.Annotations, "DaemonSet": ds.Spec.Template.Annotations,
	} {
		if a[HashAnnotation] != "h1" {
			t.Errorf("%s hash annotation = %q", kind, a[HashAnnotation])
		}
	}

	got, err = Workloads(ctx, c, "app", "creds", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("same hash restarted %v", got)
	}
}
