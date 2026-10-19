package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RolloutSpec is the desired state of a Tenarium feature rollout. A tenant
// gets the feature when the rollout is enabled, the tenant is not
// excluded, and it is either included or matches every cohort filter that
// is set (plans, regions, labels) and falls within the percentage.
// +kubebuilder:validation:XValidation:rule="has(self.feature) == has(oldSelf.feature) && (!has(self.feature) || self.feature == oldSelf.feature)",message="feature is immutable"
type RolloutSpec struct {
	// Feature is the feature the rollout turns on, e.g. "new-editor". It
	// identifies the rollout in Tenarium. Defaults to metadata.name.
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9_.:-]{0,63}$`
	// +optional
	Feature string `json:"feature,omitempty"`
	// Percentage of matching tenants (0-100) that get the feature. The
	// choice is stable: raising it keeps the tenants that already have it.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	Percentage int `json:"percentage,omitempty"`
	// Plans limits the cohort to tenants on these plans.
	// +listType=atomic
	// +optional
	Plans []string `json:"plans,omitempty"`
	// Labels limits the cohort to tenants carrying all of these labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Regions limits the cohort to tenants in these regions.
	// +listType=atomic
	// +optional
	Regions []string `json:"regions,omitempty"`
	// Include lists tenant IDs that always get the feature (unless
	// excluded).
	// +listType=atomic
	// +optional
	Include []string `json:"include,omitempty"`
	// Exclude lists tenant IDs that never get the feature.
	// +listType=atomic
	// +optional
	Exclude []string `json:"exclude,omitempty"`
	// Enabled switches the rollout on; false is the kill switch.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// DeletionPolicy decides whether deleting this resource deletes the
	// rollout in Tenarium.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// ConnectionRef selects the TenariumConnection to use. When omitted, the
	// operator's default connection is used.
	// +optional
	ConnectionRef *ConnectionReference `json:"connectionRef,omitempty"`
}

// RolloutStatus is the observed state of a Rollout.
type RolloutStatus struct {
	// Feature of the rollout in Tenarium once it is created or adopted.
	// +optional
	Feature string `json:"feature,omitempty"`
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastSyncTime is when the rollout was last compared with Tenarium.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// Conditions: Ready and Synced.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Rollout is a Tenarium feature rollout: a feature turned on gradually,
// independently of plans. Rollouts are platform-only: the API key needs
// plans:write.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=tenarium
// +kubebuilder:printcolumn:name="Feature",type=string,JSONPath=`.status.feature`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Percentage",type=integer,JSONPath=`.spec.percentage`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Rollout struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RolloutSpec   `json:"spec,omitempty"`
	Status RolloutStatus `json:"status,omitempty"`
}

// RolloutList is a list of Rollouts.
//
// +kubebuilder:object:root=true
type RolloutList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rollout `json:"items"`
}

// FeatureName returns spec.feature, defaulting to the object name.
func (r *Rollout) FeatureName() string {
	if r.Spec.Feature != "" {
		return r.Spec.Feature
	}
	return r.Name
}

func init() {
	SchemeBuilder.Register(&Rollout{}, &RolloutList{})
}
