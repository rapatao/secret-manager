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

func deployment(name string, annotated bool, secret string) *appsv1.Deployment {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name}}
	if annotated {
		d.Annotations = map[string]string{Annotation: "true"}
	}
	d.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}}}}
	return d
}

func TestDeployments(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithObjects(
		deployment("annotated", true, "creds"),
		deployment("not-annotated", false, "creds"),
		deployment("other-secret", true, "other"),
	).Build()

	got, err := Deployments(ctx, c, "app", "creds", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"annotated"}; !slices.Equal(got, want) {
		t.Fatalf("restarted %v, want %v", got, want)
	}

	var d appsv1.Deployment
	if err := c.Get(ctx, client.ObjectKey{Namespace: "app", Name: "annotated"}, &d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations[HashAnnotation] != "h1" {
		t.Fatalf("hash annotation = %q", d.Spec.Template.Annotations[HashAnnotation])
	}

	got, err = Deployments(ctx, c, "app", "creds", "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("same hash restarted %v", got)
	}
}
