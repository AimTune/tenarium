package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TemplateRole is a custom role a template creates in new tenants.
type TemplateRole struct {
	// Name of the role, e.g. "billing-admin". It cannot be a built-in role.
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9_.:-]{0,63}$`
	Name string `json:"name"`
	// +optional
	Description string `json:"description,omitempty"`
	// Actions (or action patterns such as "tenants:*") the role allows.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=atomic
	Actions []string `json:"actions"`
}

// TenantTemplateSpec is the desired state of a Tenarium tenant template.
// Tenants created from the template (spec.template of a Tenant) get these
// values unless they set their own.
// +kubebuilder:validation:XValidation:rule="has(self.id) == has(oldSelf.id) && (!has(self.id) || self.id == oldSelf.id)",message="id is immutable"
type TenantTemplateSpec struct {
	// ID of the template in Tenarium, e.g. "startup". Defaults to
	// metadata.name.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +optional
	ID string `json:"id,omitempty"`
	// Name is the display name. Defaults to the ID.
	// +kubebuilder:validation:MaxLength=200
	// +optional
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MaxLength=1000
	// +optional
	Description string `json:"description,omitempty"`
	// Plan of new tenants. It must exist in Tenarium.
	// +optional
	Plan string `json:"plan,omitempty"`
	// AddOns of new tenants.
	// +kubebuilder:validation:MaxItems=20
	// +listType=atomic
	// +optional
	AddOns []string `json:"addOns,omitempty"`
	// Region of new tenants.
	// +optional
	Region string `json:"region,omitempty"`
	// Labels of new tenants.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Settings are the base that new tenants' settings are merged onto.
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	// +optional
	Settings *runtime.RawExtension `json:"settings,omitempty"`
	// Features overrides of new tenants.
	// +optional
	Features map[string]bool `json:"features,omitempty"`
	// Limits overrides of new tenants.
	// +optional
	Limits map[string]int64 `json:"limits,omitempty"`
	// Branding of new tenants.
	// +optional
	Branding *Branding `json:"branding,omitempty"`
	// Roles are custom roles created in new tenants.
	// +listType=map
	// +listMapKey=name
	// +optional
	Roles []TemplateRole `json:"roles,omitempty"`
	// DeletionPolicy decides whether deleting this resource deletes the
	// template in Tenarium.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// ConnectionRef selects the TenariumConnection to use. When omitted, the
	// operator's default connection is used.
	// +optional
	ConnectionRef *ConnectionReference `json:"connectionRef,omitempty"`
}

// TenantTemplateStatus is the observed state of a TenantTemplate.
type TenantTemplateStatus struct {
	// ID of the template in Tenarium once it is created or adopted.
	// +optional
	ID string `json:"id,omitempty"`
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastSyncTime is when the template was last compared with Tenarium.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// Conditions: Ready and Synced.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TenantTemplate is a Tenarium tenant template: presets for new tenants
// (plan, add-ons, region, labels, settings, features, limits, branding and
// custom roles). Templates are platform-only: the API key needs
// plans:write. Tenants keep no link to the template they were created
// from, so changing a template does not change existing tenants.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ttpl,categories=tenarium
// +kubebuilder:printcolumn:name="Template ID",type=string,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Plan",type=string,JSONPath=`.spec.plan`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TenantTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantTemplateSpec   `json:"spec,omitempty"`
	Status TenantTemplateStatus `json:"status,omitempty"`
}

// TenantTemplateList is a list of TenantTemplates.
//
// +kubebuilder:object:root=true
type TenantTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TenantTemplate `json:"items"`
}

// TemplateID returns spec.id, defaulting to the object name.
func (t *TenantTemplate) TemplateID() string {
	if t.Spec.ID != "" {
		return t.Spec.ID
	}
	return t.Name
}

func init() {
	SchemeBuilder.Register(&TenantTemplate{}, &TenantTemplateList{})
}
