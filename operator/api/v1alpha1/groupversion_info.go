// Package v1alpha1 contains the tenarium.io/v1alpha1 API: Tenant, Plan,
// Rollout, TenantTemplate and TenariumConnection.
//
// +kubebuilder:object:generate=true
// +groupName=tenarium.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of these resources.
	GroupVersion = schema.GroupVersion{Group: "tenarium.io", Version: "v1alpha1"}

	// SchemeBuilder collects the types of this package.
	SchemeBuilder = &schemeBuilder{}

	// AddToScheme adds the types of this package to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// schemeBuilder registers types with a scheme using only apimachinery, so
// importing this API package does not pull in controller-runtime.
type schemeBuilder struct{ objects []runtime.Object }

// Register adds objects to be registered under GroupVersion.
func (b *schemeBuilder) Register(objects ...runtime.Object) {
	b.objects = append(b.objects, objects...)
}

// AddToScheme registers the collected types under GroupVersion.
func (b *schemeBuilder) AddToScheme(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, b.objects...)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
