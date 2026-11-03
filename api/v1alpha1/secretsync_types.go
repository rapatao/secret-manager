package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreationPolicy defines what happens to a target Secret when its SecretSync
// is deleted or the target is removed from the spec.
// +kubebuilder:validation:Enum=Owner;Orphan
type CreationPolicy string

const (
	// CreationPolicyOwner deletes the target Secret together with the SecretSync.
	CreationPolicyOwner CreationPolicy = "Owner"
	// CreationPolicyOrphan keeps the target Secret.
	CreationPolicyOrphan CreationPolicy = "Orphan"
)

// ConditionReady reports whether every target is in sync.
const ConditionReady = "Ready"

// Source is a secret path read by a SecretSync.
type Source struct {
	// Path of the secrets, like /kubernetes/app.
	// +kubebuilder:validation:Pattern=`^/([a-z0-9-]+(/[a-z0-9-]+)*)?/?$`
	Path string `json:"path"`
	// Recursive also reads every path nested below Path. Paths are merged in
	// alphabetical order, so on duplicate keys a nested path wins over its
	// parents.
	// +optional
	Recursive bool `json:"recursive,omitempty"`
}

// TargetMetadata is copied to the target Secret.
type TargetMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Template shapes the data of a target Secret.
type Template struct {
	// Data maps each target key to a Go template. Source values are available
	// as {{ .KEY }}.
	Data map[string]string `json:"data"`
}

// Target is a Secret written by a SecretSync.
type Target struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Namespace of the Secret. Defaults to the SecretSync namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:default=Owner
	// +optional
	CreationPolicy CreationPolicy `json:"creationPolicy,omitempty"`
	// Type of the Secret. Defaults to Opaque.
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
	// +optional
	Metadata TargetMetadata `json:"metadata,omitempty"`
	// Template shapes the Secret data. Without it every source key is copied.
	// +optional
	Template *Template `json:"template,omitempty"`
}

// SecretSyncSpec defines the sources to read and the Secrets to write.
type SecretSyncSpec struct {
	// Sources are merged in order; later sources win on duplicate keys.
	// +kubebuilder:validation:MinItems=1
	Sources []Source `json:"sources"`
	// RefreshInterval is the resync period. Changes made through
	// secret-manager are applied immediately.
	// +kubebuilder:default="60s"
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`
	// +kubebuilder:validation:MinItems=1
	Targets []Target `json:"targets"`
}

// SecretSyncStatus is the observed state of a SecretSync.
type SecretSyncStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastSyncedHash is the hash of the source data last written.
	// +optional
	LastSyncedHash string `json:"lastSyncedHash,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SecretSync syncs secret-manager paths into Kubernetes Secrets.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SecretSync struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretSyncSpec   `json:"spec,omitempty"`
	Status SecretSyncStatus `json:"status,omitempty"`
}

// SecretSyncList contains a list of SecretSync.
// +kubebuilder:object:root=true
type SecretSyncList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretSync `json:"items"`
}
