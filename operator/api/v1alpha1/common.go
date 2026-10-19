package v1alpha1

// Annotations, finalizers and labels used by the operator.
const (
	// AnnotationAdopt, set to "true", lets the operator take over a Tenarium
	// object that already exists (matched by tenant slug or plan ID). Without
	// it an existing object is never touched.
	AnnotationAdopt = "tenarium.io/adopt"

	// Finalizer is added to every managed object so the remote object can be
	// cleaned up according to the deletion policy.
	Finalizer = "tenarium.io/finalizer"

	// OwnerLabel is set on tenants created by the operator; its value is the
	// UID of the Tenant custom resource. It lets the operator recognize its
	// own tenants after a crash between creating the tenant and recording
	// its ID in the status.
	OwnerLabel = "tenarium.io/k8s-owner"
)

// Condition types.
const (
	// ConditionReady is true when the remote object exists and is usable
	// (for tenants: status active).
	ConditionReady = "Ready"
	// ConditionSynced is true when the last reconciliation brought the remote
	// object in line with the spec.
	ConditionSynced = "Synced"
)

// DeletionPolicy decides what happens to the remote object when the custom
// resource is deleted.
// +kubebuilder:validation:Enum=Delete;Orphan
type DeletionPolicy string

const (
	// DeletionPolicyDelete deletes the remote object.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyOrphan leaves the remote object in Tenarium.
	DeletionPolicyOrphan DeletionPolicy = "Orphan"
)

// ConnectionReference names a TenariumConnection in the same namespace.
type ConnectionReference struct {
	// Name of the TenariumConnection.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// Branding customises a tenant's sign-in pages, emails and application
// shell. URLs must be https; colors are hex values like #1a2b3c.
type Branding struct {
	// +kubebuilder:validation:MaxLength=200
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// +kubebuilder:validation:Pattern=`^https://.+`
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	LogoURL string `json:"logoUrl,omitempty"`
	// +kubebuilder:validation:Pattern=`^https://.+`
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	IconURL string `json:"iconUrl,omitempty"`
	// +kubebuilder:validation:Pattern=`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`
	// +optional
	PrimaryColor string `json:"primaryColor,omitempty"`
	// +kubebuilder:validation:Pattern=`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`
	// +optional
	AccentColor string `json:"accentColor,omitempty"`
	// +optional
	SupportEmail string `json:"supportEmail,omitempty"`
	// +kubebuilder:validation:Pattern=`^https://.+`
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	SupportURL string `json:"supportUrl,omitempty"`
}
