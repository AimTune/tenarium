package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ParentReference points at the parent tenant, either as a Tenant resource
// in the same namespace (Name) or as an existing Tenarium tenant (Slug).
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.slug)",message="set exactly one of name and slug"
type ParentReference struct {
	// Name of a Tenant resource in the same namespace. The child waits until
	// that Tenant is Ready.
	// +optional
	Name string `json:"name,omitempty"`
	// Slug (or ID) of a tenant that exists in Tenarium.
	// +optional
	Slug string `json:"slug,omitempty"`
}

// ScheduledAction is an action Tenarium runs later for the tenant, e.g. the
// end of a trial.
// +kubebuilder:validation:XValidation:rule="has(self.at) != has(self.after)",message="set exactly one of at and after"
// +kubebuilder:validation:XValidation:rule="self.action != 'set_plan' || has(self.plan)",message="plan is required for set_plan"
type ScheduledAction struct {
	// Action to run.
	// +kubebuilder:validation:Enum=suspend;resume;set_plan;delete
	Action string `json:"action"`
	// At is an absolute run time.
	// +optional
	At *metav1.Time `json:"at,omitempty"`
	// After is relative to when the action is scheduled: a duration ("36h")
	// or days ("14d").
	// +kubebuilder:validation:Pattern=`^([0-9]+d|([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+)$`
	// +optional
	After string `json:"after,omitempty"`
	// Plan for set_plan.
	// +optional
	Plan string `json:"plan,omitempty"`
	// Reason for suspend.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// TenantSpec is the desired state of a Tenarium tenant.
//
// Optional map fields are managed only when set: leaving labels, settings,
// features or limits out keeps whatever the tenant has in Tenarium.
//
// +kubebuilder:validation:XValidation:rule="self.slug == oldSelf.slug",message="slug is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.parent) == has(oldSelf.parent) && (!has(self.parent) || self.parent == oldSelf.parent)",message="parent is immutable"
type TenantSpec struct {
	// Slug is the tenant's unique, URL-safe identifier. It cannot change.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	Slug string `json:"slug"`
	// Name is the display name. Defaults to the slug.
	// +kubebuilder:validation:MaxLength=200
	// +optional
	Name string `json:"name,omitempty"`
	// Plan is the ID of the tenant's plan. When omitted, the plan is not
	// managed.
	// +optional
	Plan string `json:"plan,omitempty"`
	// Parent makes the tenant a child of another tenant. It cannot change.
	// +optional
	Parent *ParentReference `json:"parent,omitempty"`
	// Labels replace the tenant's labels (the operator adds its owner label).
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Settings is the tenant's free-form settings object. Keys missing here
	// are removed from the tenant.
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	// +optional
	Settings *runtime.RawExtension `json:"settings,omitempty"`
	// Features override the plan's features.
	// +optional
	Features map[string]bool `json:"features,omitempty"`
	// Limits override the plan's limits.
	// +optional
	Limits map[string]int64 `json:"limits,omitempty"`
	// AddOns are plan IDs stacked on the plan. When omitted, the add-ons
	// are not managed; an empty list removes them.
	// +kubebuilder:validation:MaxItems=20
	// +listType=atomic
	// +optional
	AddOns []string `json:"addOns"`
	// PlanRevision pins the tenant to a revision of its plan
	// (grandfathering); 0 follows the plan's current definition. When
	// omitted, the pin is not managed.
	// +kubebuilder:validation:Minimum=0
	// +optional
	PlanRevision *int64 `json:"planRevision,omitempty"`
	// Region places the tenant (data residency). It is set when the tenant
	// is created; changing it later moves the tenant to the new region
	// (POST /v1/tenants/{id}/move, which needs tenants:move). When omitted,
	// the region is not managed.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +optional
	Region string `json:"region,omitempty"`
	// MoveReprovision makes a region move run the provisioners in the new
	// region, inside a maintenance window that ends when they succeed.
	// +optional
	MoveReprovision bool `json:"moveReprovision,omitempty"`
	// BillingAnchor starts the tenant's monthly billing cycles. Removing it
	// from a spec that set it removes the anchor in Tenarium; when never
	// set, an anchor set elsewhere (e.g. by a billing plugin) is kept.
	// +optional
	BillingAnchor *metav1.Time `json:"billingAnchor,omitempty"`
	// Branding customises the tenant's sign-in pages and emails. Removing
	// it from a spec that set it clears the branding in Tenarium; an empty
	// object clears it too. A tenant whose spec never set branding keeps
	// its own.
	// +optional
	Branding *Branding `json:"branding,omitempty"`
	// Template is the ID of a tenant template that presets the tenant when
	// it is created (the spec's own values win). It is used only on
	// creation: changing it later has no effect.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +optional
	Template string `json:"template,omitempty"`
	// Schedule lists actions Tenarium runs later. Each entry is scheduled
	// once; removing a pending entry cancels it.
	// +listType=atomic
	// +optional
	Schedule []ScheduledAction `json:"schedule,omitempty"`
	// DeletionPolicy decides whether deleting this resource deletes the
	// tenant in Tenarium.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// ConnectionRef selects the TenariumConnection to use. When omitted, the
	// operator's default connection is used.
	// +optional
	ConnectionRef *ConnectionReference `json:"connectionRef,omitempty"`
}

// EntitlementsSummary is the tenant's effective plan, features and limits.
type EntitlementsSummary struct {
	// +optional
	Plan string `json:"plan,omitempty"`
	// EnabledFeatures lists the enabled features, sorted.
	// +optional
	EnabledFeatures []string `json:"enabledFeatures,omitempty"`
	// +optional
	Limits map[string]int64 `json:"limits,omitempty"`
}

// ScheduledActionStatus records an action the operator scheduled.
type ScheduledActionStatus struct {
	// Key identifies the spec entry (a hash of its fields).
	Key string `json:"key"`
	// ID of the scheduled action in Tenarium.
	ID string `json:"id"`
	// +optional
	Action string `json:"action,omitempty"`
	// +optional
	RunAt *metav1.Time `json:"runAt,omitempty"`
	// State: pending, running, done, failed or canceled.
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Error string `json:"error,omitempty"`
}

// MaintenanceStatus describes a tenant's maintenance window.
type MaintenanceStatus struct {
	// Active is true while the window is open: the tenant is read-only for
	// its own users.
	Active bool `json:"active"`
	// +optional
	Message string `json:"message,omitempty"`
	// Until is when the window ends by itself, if set.
	// +optional
	Until *metav1.Time `json:"until,omitempty"`
	// MoveTo is the region a reprovisioning move is heading to.
	// +optional
	MoveTo string `json:"moveTo,omitempty"`
}

// HealthStatus is a tenant's health score.
type HealthStatus struct {
	// Score from 0 (unhealthy) to 100.
	Score int `json:"score"`
	// Grade summarizes the score, e.g. "A".
	// +optional
	Grade string `json:"grade,omitempty"`
}

// TenantStatus is the observed state of a Tenant.
type TenantStatus struct {
	// ID of the tenant in Tenarium.
	// +optional
	ID string `json:"id,omitempty"`
	// ParentID is the Tenarium ID of the parent tenant.
	// +optional
	ParentID string `json:"parentID,omitempty"`
	// Phase is the tenant's Tenarium status: provisioning, active,
	// suspended, failed, deleting or deleted.
	// +optional
	Phase string `json:"phase,omitempty"`
	// StatusReason explains the phase (e.g. why provisioning failed).
	// +optional
	StatusReason string `json:"statusReason,omitempty"`
	// Version is the remote object version last seen.
	// +optional
	Version int64 `json:"version,omitempty"`
	// Adopted is true when the tenant existed before and was adopted.
	// +optional
	Adopted bool `json:"adopted,omitempty"`
	// Entitlements is the tenant's effective plan, features and limits.
	// +optional
	Entitlements *EntitlementsSummary `json:"entitlements,omitempty"`
	// PlanRevision is the plan revision the tenant is pinned to; 0 follows
	// the plan's current definition.
	// +optional
	PlanRevision int64 `json:"planRevision,omitempty"`
	// Region is the tenant's region in Tenarium.
	// +optional
	Region string `json:"region,omitempty"`
	// BrandingManaged is true when the operator applied spec.branding, so
	// removing spec.branding clears the branding in Tenarium.
	// +optional
	BrandingManaged bool `json:"brandingManaged,omitempty"`
	// BillingAnchorManaged is true when the operator applied
	// spec.billingAnchor, so removing it removes the anchor in Tenarium.
	// +optional
	BillingAnchorManaged bool `json:"billingAnchorManaged,omitempty"`
	// Maintenance is the tenant's maintenance window, while one is active.
	// +optional
	Maintenance *MaintenanceStatus `json:"maintenance,omitempty"`
	// Health is the tenant's health score, refreshed on every sync.
	// +optional
	Health *HealthStatus `json:"health,omitempty"`
	// ScheduledActions are the actions scheduled from spec.schedule.
	// +optional
	ScheduledActions []ScheduledActionStatus `json:"scheduledActions,omitempty"`
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastSyncTime is when the tenant was last compared with Tenarium.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// Conditions: Ready and Synced.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Tenant is a Tenarium tenant managed from Kubernetes.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tnt,categories=tenarium
// +kubebuilder:printcolumn:name="Slug",type=string,JSONPath=`.spec.slug`
// +kubebuilder:printcolumn:name="Plan",type=string,JSONPath=`.spec.plan`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Region",type=string,JSONPath=`.status.region`,priority=1
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.health.grade`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.status.id`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantSpec   `json:"spec"`
	Status TenantStatus `json:"status,omitempty"`
}

// TenantList is a list of Tenants.
//
// +kubebuilder:object:root=true
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Tenant{}, &TenantList{})
}
