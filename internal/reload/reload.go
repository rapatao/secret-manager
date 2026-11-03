// Package reload restarts Deployments that use a changed Secret.
package reload

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Annotation opts a Deployment into automatic restarts.
	Annotation = "secretmanager.rapatao.com/auto-reload"
	// HashAnnotation is set on the pod template to trigger a rollout.
	HashAnnotation = "secretmanager.rapatao.com/secret-hash"
)

// Deployments sets HashAnnotation to hash on the pod template of every
// Deployment in namespace that opted in and references secretName, which
// rolls out new pods. It returns the names of the restarted Deployments.
func Deployments(ctx context.Context, c client.Client, namespace, secretName, hash string) ([]string, error) {
	var list appsv1.DeploymentList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	var restarted []string
	for i := range list.Items {
		d := &list.Items[i]
		if d.Annotations[Annotation] != "true" ||
			d.Spec.Template.Annotations[HashAnnotation] == hash ||
			!References(&d.Spec.Template.Spec, secretName) {
			continue
		}
		patch := client.MergeFrom(d.DeepCopy())
		if d.Spec.Template.Annotations == nil {
			d.Spec.Template.Annotations = map[string]string{}
		}
		d.Spec.Template.Annotations[HashAnnotation] = hash
		if err := c.Patch(ctx, d, patch); err != nil {
			return restarted, fmt.Errorf("patch deployment %s: %w", d.Name, err)
		}
		restarted = append(restarted, d.Name)
	}
	return restarted, nil
}

// References reports whether spec uses secret name through envFrom, env,
// volumes or projected volumes, in containers or init containers.
func References(spec *corev1.PodSpec, name string) bool {
	containers := append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
	for _, c := range containers {
		for _, e := range c.EnvFrom {
			if e.SecretRef != nil && e.SecretRef.Name == name {
				return true
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && e.ValueFrom.SecretKeyRef.Name == name {
				return true
			}
		}
	}
	for _, v := range spec.Volumes {
		if v.Secret != nil && v.Secret.SecretName == name {
			return true
		}
		if v.Projected == nil {
			continue
		}
		for _, s := range v.Projected.Sources {
			if s.Secret != nil && s.Secret.Name == name {
				return true
			}
		}
	}
	return false
}
