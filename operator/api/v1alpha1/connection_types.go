package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeyReference selects a key of a Secret in the same namespace.
type SecretKeyReference struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key in the Secret's data.
	// +kubebuilder:default=api-key
	// +optional
	Key string `json:"key,omitempty"`
}

// TenariumConnectionSpec says how to reach a Tenarium server.
type TenariumConnectionSpec struct {
	// URL of the Tenarium server, e.g. https://tenarium.example.com.
	// +kubebuilder:validation:Pattern=`^https?://.+`
	URL string `json:"url"`
	// APIKeySecretRef selects the API key. The key needs tenants:* and
	// plans:* permissions for the resources that use this connection.
	APIKeySecretRef SecretKeyReference `json:"apiKeySecretRef"`
}

// TenariumConnectionStatus is the observed state of a TenariumConnection.
type TenariumConnectionStatus struct {
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Principal is the identity the API key authenticates as.
	// +optional
	Principal string `json:"principal,omitempty"`
	// Conditions: Ready is true when the server accepted the credentials.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TenariumConnection holds the URL and credentials of a Tenarium server.
// Tenants, Plans, Rollouts and TenantTemplates refer to it with
// spec.connectionRef; without one they use the connection given by the
// operator's command-line flags.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tconn,categories=tenarium
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TenariumConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenariumConnectionSpec   `json:"spec"`
	Status TenariumConnectionStatus `json:"status,omitempty"`
}

// TenariumConnectionList is a list of TenariumConnections.
//
// +kubebuilder:object:root=true
type TenariumConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TenariumConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TenariumConnection{}, &TenariumConnectionList{})
}
