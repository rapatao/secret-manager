// Package v1alpha1 contains the secretmanager.rapatao.com/v1alpha1 API.
// +kubebuilder:object:generate=true
// +groupName=secretmanager.rapatao.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of this API.
	GroupVersion = schema.GroupVersion{Group: "secretmanager.rapatao.com", Version: "v1alpha1"}

	// SchemeBuilder registers the types of this API.
	SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SecretSync{}, &SecretSyncList{})
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})

	// AddToScheme adds the types of this API to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
