// Package reload restarts Deployments, StatefulSets and DaemonSets that use a
// changed Secret.
package reload

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Annotation opts a workload into automatic restarts.
	Annotation = "secretmanager.rapatao.com/auto-reload"
	// HashAnnotation is set on the pod template to trigger a rollout.
	HashAnnotation = "secretmanager.rapatao.com/secret-hash"
)

// Workloads sets HashAnnotation to hash on the pod template of every
// Deployment, StatefulSet and DaemonSet in namespace that opted in and
// references secretName, which rolls out new pods. It returns the restarted
// workloads as Kind/name.
func Workloads(ctx context.Context, c client.Client, namespace, secretName, hash string) ([]string, error) {
	var (
		deployments  appsv1.DeploymentList
		statefulSets appsv1.StatefulSetList
		daemonSets   appsv1.DaemonSetList
	)
	for _, list := range []client.ObjectList{&deployments, &statefulSets, &daemonSets} {
		if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
			return nil, fmt.Errorf("list workloads: %w", err)
		}
	}
	type workload struct {
		kind     string
		obj      client.Object
		template *corev1.PodTemplateSpec
	}
	var workloads []workload
	for i := range deployments.Items {
		w := &deployments.Items[i]
		workloads = append(workloads, workload{"Deployment", w, &w.Spec.Template})
	}
	for i := range statefulSets.Items {
		w := &statefulSets.Items[i]
		workloads = append(workloads, workload{"StatefulSet", w, &w.Spec.Template})
	}
	for i := range daemonSets.Items {
		w := &daemonSets.Items[i]
		workloads = append(workloads, workload{"DaemonSet", w, &w.Spec.Template})
	}

	var restarted []string
	for _, w := range workloads {
		if w.obj.GetAnnotations()[Annotation] != "true" ||
			w.template.Annotations[HashAnnotation] == hash ||
			!References(&w.template.Spec, secretName) {
			continue
		}
		patch := client.MergeFrom(w.obj.DeepCopyObject().(client.Object))
		if w.template.Annotations == nil {
			w.template.Annotations = map[string]string{}
		}
		w.template.Annotations[HashAnnotation] = hash
		name := w.kind + "/" + w.obj.GetName()
		if err := c.Patch(ctx, w.obj, patch); err != nil {
			return restarted, fmt.Errorf("patch %s: %w", name, err)
		}
		restarted = append(restarted, name)
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
