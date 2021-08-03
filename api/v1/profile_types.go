/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	ProfileSucceed = "Successful"
	ProfileFailed  = "Failed"
	ProfileUnknown = "Unknown"
)

type ProfileCondition struct {
	Type    string `json:"type,omitempty"`
	Status  string `json:"status,omitempty" description:"status of the condition, one of True, False, Unknown"`
	Message string `json:"message,omitempty"`
}

// Plugin is for customize actions on different platform.
type Plugin struct {
	metav1.TypeMeta `json:",inline"`
	// +kubebuilder:pruning:PreserveUnknownFields
	Spec *runtime.RawExtension `json:"spec,omitempty"`
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ProfileSpec defines the desired state of Profile
type ProfileSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of Profile. Edit profile_types.go to remove/update
	// Foo string `json:"foo,omitempty"`
	Owner   rbacv1.Subject `json:"owner,omitempty"`
	Plugins []Plugin       `json:"plugins,omitempty"`
	// Plugins []
	ResourceQuotaSpec v1.ResourceQuotaSpec `json:"resourceQuotaSpec,omitempty"`
}

// ProfileStatus defines the observed state of Profile
type ProfileStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Conditions []ProfileCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Profile is the Schema for the profiles API
type Profile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProfileSpec   `json:"spec,omitempty"`
	Status ProfileStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ProfileList contains a list of Profile
type ProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Profile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Profile{}, &ProfileList{})
}
