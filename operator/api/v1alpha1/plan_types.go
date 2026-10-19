package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PlanSpec is the desired state of a Tenarium plan.
// +kubebuilder:validation:XValidation:rule="has(self.id) == has(oldSelf.id) && (!has(self.id) || self.id == oldSelf.id)",message="id is immutable"
type PlanSpec struct {
	// ID of the plan in Tenarium, e.g. "pro". Defaults to metadata.name.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +optional
	ID string `json:"id,omitempty"`
	// Name is the display name. Defaults to the ID.
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	Description string `json:"description,omitempty"`
	// Features enabled by the plan. When omitted, the operator does not
	// manage the plan's features.
	// +optional
	Features map[string]bool `json:"features,omitempty"`
	// Limits of the plan, by metric. When omitted, the operator does not
	// manage the plan's limits.
	// +optional
	Limits map[string]int64 `json:"limits,omitempty"`
	// DeletionPolicy decides whether deleting this resource deletes the plan
	// in Tenarium.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// ConnectionRef selects the TenariumConnection to use. When omitted, the
	// operator's default connection is used.
	// +optional
	ConnectionRef *ConnectionReference `json:"connectionRef,omitempty"`
}

// PlanStatus is the observed state of a Plan.
type PlanStatus struct {
	// ID of the plan in Tenarium once it is created or adopted.
	// +optional
	ID string `json:"id,omitempty"`
	// Version is the remote object version last seen.
	// +optional
	Version int64 `json:"version,omitempty"`
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastSyncTime is when the plan was last compared with Tenarium.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// Conditions: Ready and Synced.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Plan is a Tenarium plan: a bundle of features and limits.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=tenarium
// +kubebuilder:printcolumn:name="Plan ID",type=string,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Plan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlanSpec   `json:"spec,omitempty"`
	Status PlanStatus `json:"status,omitempty"`
}

// PlanList is a list of Plans.
//
// +kubebuilder:object:root=true
type PlanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Plan `json:"items"`
}

// PlanID returns spec.id, defaulting to the object name.
func (p *Plan) PlanID() string {
	if p.Spec.ID != "" {
		return p.Spec.ID
	}
	return p.Name
}

func init() {
	SchemeBuilder.Register(&Plan{}, &PlanList{})
}
