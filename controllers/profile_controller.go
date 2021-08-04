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

package controllers

import (
	"context"
	"fmt"
	"github.com/cenkalti/backoff"
	"github.com/ghodss/yaml"
	"github.com/go-logr/logr"
	istioSecurity "istio.io/api/security/v1beta1"
	istioSecurityClient "istio.io/client-go/pkg/apis/security/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	icodeaiv1 "github.com/chepkoyallan/one/api/v1"
	corev1 "k8s.io/api/core/v1"
)

const AUTHZPOLICYISTIO = "ns-owner-access-istio"

// annotation key, consumed by kfam API
const USER = "user"
const ROLE = "role"
const ADMIN = "admin"

const (
	Admin               = "icodeai-admin"
	Edit                = "icodeai-edit"
	View                = "icodeai-view"
	IstioInjectionLabel = "istio-injection"
)

const DEFAULT_EDITOR = "default-editor"
const DEFAULT_VIEWER = "default-viewer"
const ICODEAIQUOTA = "kf-resource-quota"
const PROFILEFINALIZER = "profile-finalizer"

var NamespaceLabels = map[string]string{
	"katib-metricscollector-injection":      "enabled",
	"serving.kubeflow.org/inferenceservice": "enabled",
	"pipelines.kubeflow.org/enabled":        "true",
	"app.kubernetes.io/part-of":             "kubeflow-profile",
}

// ProfileReconciler reconciles a Profile object
type ProfileReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Log              logr.Logger
	UserIdHeader     string
	UserIDPrefix     string
	WorkloadIdentity string
}
type Plugin interface {
	// Called when profile CR is created / updated
	ApplyPlugin(*ProfileReconciler, *icodeaiv1.Profile) error
	// Called when profile CR is being deleted, to cleanup any non-k8s resources created via ApplyPlugin
	// RevokePlugin logic need to be IDEMPOTENT
	RevokePlugin(*ProfileReconciler, *icodeaiv1.Profile) error
}

//+kubebuilder:rbac:groups=icodeai.icodeai.io,resources=profiles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=icodeai.icodeai.io,resources=profiles/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=icodeai.icodeai.io,resources=profiles/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Profile object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// your logic here
	//ctx := context.Background()
	logger := r.Log.WithValues("profile", req.NamespacedName)

	//Fetch the profile instance
	instance := &icodeaiv1.Profile{}
	logger.Info("Start to Reconcile", "namespace", "name", req.Name)
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			//Object not found, return. Created objects are automatically garbage collected
			//for additional cleanup logic use finalizers
			IncRequestCounter("Profile deletion")
			return reconcile.Result{}, nil
		}
		//Error reading the object - requeue the request
		IncRequestErrorCounter("error reading the profile object", SEVERITY_MAJOR)
		logger.Error(err, "error reading the profile object")
		return reconcile.Result{}, err

	}
	// Update Namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{"owner": instance.Spec.Owner.Name},
			// inject istio sidecar to all pods in target namespace by default
			Labels: map[string]string{
				IstioInjectionLabel: "enabled",
			},
			Name: instance.Name,
		},
	}

	updateNamespaceLabels(ns)
	if err := controllerutil.SetControllerReference(instance, ns, r.Scheme); err != nil {
		IncRequestErrorCounter("error setting ControllerReference", SEVERITY_MAJOR)
		logger.Error(err, "error setting ControllerReference")
		return reconcile.Result{}, err
	}

	// If Namespace is not found  create a if found report back
	foundNs := &corev1.Namespace{}
	err = r.Get(ctx, types.NamespacedName{Name: ns.Name}, foundNs)

	// if there is no error and namespace is not found
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating Namespace: " + ns.Name)
			// create ns
			err = r.Create(ctx, ns)
			// Error found
			if err != nil {
				IncRequestErrorCounter("error creating namespace", SEVERITY_MAJOR)
				logger.Error(err, "error creating namespace")
				return reconcile.Result{}, err
			}
			//if error is nil i.e not found
			// wait for 15 sec for new namespace creation
			err = backoff.Retry(
				func() error {
					return r.Get(ctx, types.NamespacedName{Name: ns.Name}, foundNs)
				},
				backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5))
			if err != nil {
				IncRequestErrorCounter("error namespace create completion", SEVERITY_MAJOR)
				logger.Error(err, "error namespace completion")
				return r.appendErrorConditionAndReturn(ctx, instance, "Owning namespace failed to create within 15 seconds")
			}
			logger.Info("Created Namespace: "+foundNs.Name, "status", foundNs.Status.Phase)
		} else {
			IncRequestErrorCounter("error reading namespace", SEVERITY_MAJOR)
			logger.Error(err, "error reading namespace")
		}
	} else {
		//Check existing namespace ownwership before move forward
		owner, ok := foundNs.Annotations["owner"]
		if ok && owner == instance.Spec.Owner.Name {
			if updated := updateNamespaceLabels(foundNs); updated {
				err = r.Update(ctx, foundNs)
				if err != nil {
					IncRequestErrorCounter("Error updating namespace label", SEVERITY_MAJOR)
					logger.Error(err, "error updating namespace label")
					return reconcile.Result{}, err
				}
			}
		} else {
			logger.Info(fmt.Sprintf("namespace already exist, but not owned by profile creator %v",
				instance.Spec.Owner.Name))
			IncRequestCounter("reject profile taking over existing namespace")
			return r.appendErrorConditionAndReturn(ctx, instance, fmt.Sprintf(
				"namespace already exist, nut not owned by profile %v", instance.Spec.Owner.Name))
		}
	}

	// update Istio Authorizatio Policy
	// Create Istio AuthorizationPolicy in target namespace, which will give ns owner permission to access services in ns.

	if err = r.updateIstioAuthorizationPolicy(instance); err != nil {
		logger.Error(err, "error Updating Istio Authorization permission", "namespace", instance.Name)
		logger.Error(err, "error updating Istio AuthorizationPolicy permission", SEVERITY_MAJOR)
		return reconcile.Result{}, err
	}

	// Update service accounts
	// Create service account "default-editor" in target namespace.
	// "default-editor" would have kubeflowEdit permission: edit all resources in target namespace except rbac.
	if err = r.updateServiceAccount(instance, DEFAULT_EDITOR, Edit); err != nil {
		logger.Error(err, "error updating Service account", "namespace", instance.Name, "name", "defaultEditor")
		IncRequestErrorCounter("error updating ServiceAccount", SEVERITY_MAJOR)
		return reconcile.Result{}, err
	}
	// Create service account "default-viewer" in target namespace.
	// "default-viewer" would have k8s default "view" permission: view all resources in target namespace.
	if err = r.updateServiceAccount(instance, DEFAULT_VIEWER, View); err != nil {
		logger.Error(err, "error updating service account", "namespace", instance.Name, "name", "defaultViewer")
		IncRequestErrorCounter("error updating service account", SEVERITY_MAJOR)
		return reconcile.Result{}, err
	}

	// Update owner rbac permission
	// When ClusterRole was referred by namespaced roleBinding, the result permission will be namespaced as well.
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{USER: instance.Spec.Owner.Name, ROLE: ADMIN},
			Name:        "namespaceAdmin",
			Namespace:   instance.Name,
		},
		// Use default cluster role 'admin for profile/namespace owner
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "IcodeAIAdmin",
		},
		Subjects: []rbacv1.Subject{
			instance.Spec.Owner,
		},
	}
	if err = r.updateRoleBinding(instance, roleBinding); err != nil {
		logger.Error(err, "error Updating Owner Rolebinding", "namespace", instance.Name, "name", "defaultEditor")
		IncRequestErrorCounter("error updating owner rolebinding", SEVERITY_MAJOR)
		return reconcile.Result{}, err
	}

	// Create resource quota for targeted namespace if resource are specified in profile
	if len(instance.Spec.ResourceQuotaSpec.Hard) > 0 {
		resourceQuota := &corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ICODEAIQUOTA,
				Namespace: instance.Name,
			},
			Spec: instance.Spec.ResourceQuotaSpec,
		}
		if err = r.updateResourceQuota(instance, resourceQuota); err != nil {
			logger.Error(err, "error updating resource quota", "namespace", instance.Name)
			IncRequestErrorCounter("error updating resource quota", SEVERITY_MAJOR)
			return reconcile.Result{}, err
		}
	} else {
		logger.Info("No update on resource quota", "spec", instance.Spec.ResourceQuotaSpec.String())
	}

	if err := r.PatchDefaultPluginSpec(ctx, instance); err != nil {
		IncRequestErrorCounter("error patching DefaultPluginSpec", SEVERITY_MAJOR)
		logger.Error(err, "Failed patching DefaultPluginSpec", "namespace", instance.Name)
		return reconcile.Result{}, err
	}

	if plugins, err := r.GetPluginSpec(instance); err == nil {
		for _, plugin := range plugins {
			if err2 := plugin.ApplyPlugin(r, instance); err2 != nil {
				logger.Error(err2, "Failed applying plugin", "namespace", instance.Name)
				IncRequestErrorCounter("error applying plugin", SEVERITY_MAJOR)
				return reconcile.Result{}, err2
			}
		}
	}

	// examine DeletionTimestamp to determine if object is under deletion
	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !containsString(instance.ObjectMeta.Finalizers, PROFILEFINALIZER) {
			instance.ObjectMeta.Finalizers = append(instance.ObjectMeta.Finalizers, PROFILEFINALIZER)
			if err := r.Update(ctx, instance); err != nil {
				logger.Error(err, "error updating finalizer", "namespace", instance.Name)
				IncRequestErrorCounter("error updating finalizer", SEVERITY_MAJOR)
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(instance.ObjectMeta.Finalizers, PROFILEFINALIZER) {
			// our finalizer is present, so lets revoke all Plugins to clean up any external dependencies
			if plugins, err := r.GetPluginSpec(instance); err == nil {
				for _, plugin := range plugins {
					if err := plugin.RevokePlugin(r, instance); err != nil {
						logger.Error(err, "error revoking plugin", "namespace", instance.Name)
						IncRequestErrorCounter("error revoking plugin", SEVERITY_MAJOR)
						return reconcile.Result{}, err
					}
				}
			}

			// remove our finalizer from the list and update it.
			instance.ObjectMeta.Finalizers = removeString(instance.ObjectMeta.Finalizers, PROFILEFINALIZER)
			if err := r.Update(ctx, instance); err != nil {
				logger.Error(err, "error removing finalizer", "namespace", instance.Name)
				IncRequestErrorCounter("error removing finalizer", SEVERITY_MAJOR)
				return ctrl.Result{}, err
			}
		}
	}
	IncRequestCounter("reconcile")
	return ctrl.Result{}, nil
}

// appendErrorConditionAndReturn append failure status to profile CR and mark Reconcile done. If update condition failed, request will be requeued.
func (r *ProfileReconciler) appendErrorConditionAndReturn(ctx context.Context, instance *icodeaiv1.Profile, message string) (ctrl.Result, error) {
	instance.Status.Conditions = append(instance.Status.Conditions, icodeaiv1.ProfileCondition{
		Type:    icodeaiv1.ProfileFailed,
		Message: message,
	})
	if err := r.Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&icodeaiv1.Profile{}).
		Complete(r)
}

func updateNamespaceLabels(ns *corev1.Namespace) bool {
	updated := false
	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	for k, v := range NamespaceLabels {
		if _, ok := ns.Labels[k]; !ok {
			ns.Labels[k] = v
			updated = true
		}
	}
	return updated
}

func (r *ProfileReconciler) getAuthorizationPolicy(profileIns *icodeaiv1.Profile) istioSecurity.AuthorizationPolicy {
	return istioSecurity.AuthorizationPolicy{
		Action: istioSecurity.AuthorizationPolicy_ALLOW,
		//Empty selector == match all workloads in namespace
		Selector: nil,
		Rules: []*istioSecurity.Rule{
			{
				When: []*istioSecurity.Condition{
					{
						// Namespace Owner can access all workloads in the
						// namespace
						Key: fmt.Sprintf("request.headers[%v]", r.UserIdHeader),
						Values: []string{
							r.UserIDPrefix + profileIns.Spec.Owner.Name,
						},
					},
				},
			},
			{
				When: []*istioSecurity.Condition{
					{
						//Workloads in the same namespace can access all other
						//workloads in the namespace
						Key:    fmt.Sprintf("source.namespace"),
						Values: []string{profileIns.Name},
					},
				},
			},
			{
				To: []*istioSecurity.Rule_To{
					{
						Operation: &istioSecurity.Operation{
							// Workloads paths should be accessible for KNative's
							// `activators` and `controller` probes
							// See: https://knative.dev/docs/serving/istio-authorization/#allowing-access-from-system-pods-by-paths
							Paths: []string{
								"/healthz",
								"/metrics",
								"/wait-for-domain",
							},
						},
					},
				},
			},
		},
	}
}

// updateIstioAuthorizationPolicy create or update Istio AuthorizationPolicy
// resources in target namespace owned by "profileIns". The goal is to allow
// service access for profile owner.
func (r *ProfileReconciler) updateIstioAuthorizationPolicy(profileIns *icodeaiv1.Profile) error {
	logger := r.Log.WithValues("profile", profileIns.Name)
	istioAuth := &istioSecurityClient.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{USER: profileIns.Spec.Owner.Name, ROLE: ADMIN},
			Name:        AUTHZPOLICYISTIO,
			Namespace:   profileIns.Name,
		},
		Spec: r.getAuthorizationPolicy(profileIns),
	}
	if err := controllerutil.SetControllerReference(profileIns, istioAuth, r.Scheme); err != nil {
		return err
	}
	foundAuthorizationPolicy := &istioSecurityClient.AuthorizationPolicy{}
	err := r.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      istioAuth.ObjectMeta.Name,
			Namespace: istioAuth.ObjectMeta.Namespace,
		},
		foundAuthorizationPolicy,
	)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating istio AuthorizationPolicy", "namespace", istioAuth.ObjectMeta.Namespace,
				"name", istioAuth.ObjectMeta.Name)
			err = r.Create(context.TODO(), istioAuth)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		if !reflect.DeepEqual(istioAuth, foundAuthorizationPolicy) {
			foundAuthorizationPolicy.Spec = istioAuth.Spec
			logger.Info("Updating Istio AuthorizationPolicy", "namespace", istioAuth.ObjectMeta.Namespace,
				"name", istioAuth.ObjectMeta.Name)
			err = r.Update(context.TODO(), foundAuthorizationPolicy)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// updateServiceAccount create or update service account "saName" with role "ClusterRoleName" in target namespace owned by "profileIns"
func (r *ProfileReconciler) updateServiceAccount(profileIns *icodeaiv1.Profile, saName string, ClusterRoleName string) error {
	logger := r.Log.WithValues("profile", profileIns.Name)
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: profileIns.Name,
		},
	}
	if err := controllerutil.SetControllerReference(profileIns, serviceAccount, r.Scheme); err != nil {
		return err
	}
	found := &corev1.ServiceAccount{}
	err := r.Get(context.TODO(), types.NamespacedName{Name: serviceAccount.Name, Namespace: serviceAccount.Namespace}, found)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating Service Account", "namespace", serviceAccount.Namespace, "name", serviceAccount.Name)
			err = r.Create(context.TODO(), serviceAccount)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: profileIns.Name,
		},
		// Use default ClusterRole 'admin' for profile/namespace owner
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "ClusterRoleName",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      saName,
				Namespace: profileIns.Name,
			},
		},
	}
	return r.updateRoleBinding(profileIns, roleBinding)
}

func (r *ProfileReconciler) updateRoleBinding(profileIns *icodeaiv1.Profile, roleBinding *rbacv1.RoleBinding) error {
	logger := r.Log.WithValues("profile", profileIns.Name)
	if err := controllerutil.SetControllerReference(profileIns, roleBinding, r.Scheme); err != nil {
		return err
	}
	found := &rbacv1.RoleBinding{}
	err := r.Get(context.TODO(), types.NamespacedName{Name: roleBinding.Name, Namespace: roleBinding.Namespace}, found)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating RoleBinding", "namespace", roleBinding.Namespace, "name", roleBinding.Name)
			err = r.Create(context.TODO(), roleBinding)
			if err != nil {
				return err
			} else {
				return err
			}
		} else {
			if !(reflect.DeepEqual(roleBinding.RoleRef, found.RoleRef) && reflect.DeepEqual(roleBinding.Subjects, found.Subjects)) {
				found.RoleRef = roleBinding.RoleRef
				found.Subjects = roleBinding.Subjects
				logger.Info("updating Rolebinding", "namespace", roleBinding.Namespace, "name", roleBinding.Name)
				err = r.Update(context.TODO(), found)
				if err != nil {
					return err
				}
			}
		}

	}
	return nil
}

//update Resource Quota create or update resource Quota for target namespace
func (r *ProfileReconciler) updateResourceQuota(profileIns *icodeaiv1.Profile, resourceQuota *corev1.ResourceQuota) error {
	ctx := context.Background()
	logger := r.Log.WithValues("profile", profileIns.Name)
	if err := controllerutil.SetControllerReference(profileIns, resourceQuota, r.Scheme); err != nil {
		return err
	}
	found := &corev1.ResourceQuota{}
	err := r.Get(ctx, types.NamespacedName{Name: resourceQuota.Name, Namespace: resourceQuota.Namespace}, found)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("creating ResourceQuota", "namespace", resourceQuota.Namespace, "name", resourceQuota.Name)
			err = r.Create(ctx, resourceQuota)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		if !(reflect.DeepEqual(resourceQuota.Spec, found.Spec)) {
			found.Spec = resourceQuota.Spec
			logger.Info("updating resource quota", "namespace", resourceQuota.Namespace, "name", resourceQuota.Name)
			err = r.Update(ctx, found)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// PatchDefaultPluginSpec patch default plugins to profile CR instance if user doesn't specify plugin of same kind in CR.
func (r *ProfileReconciler) PatchDefaultPluginSpec(ctx context.Context, profileIns *icodeaiv1.Profile) error {
	//read existing plugins into map
	plugins := make(map[string]icodeaiv1.Plugin)
	for _, p := range profileIns.Spec.Plugins {
		plugins[p.Kind] = p
	}
	//patch default plugins if same kind doesnt exist yet
	if r.WorkloadIdentity != "" {
		if _, ok := plugins[KIND_WORKLOAD_IDENTITY]; !ok {
			if _, ok := plugins[KIND_WORKLOAD_IDENTITY]; !ok {
				profileIns.Spec.Plugins = append(profileIns.Spec.Plugins, icodeaiv1.Plugin{
					TypeMeta: metav1.TypeMeta{
						Kind: KIND_WORKLOAD_IDENTITY,
					},
					Spec: &runtime.RawExtension{
						Raw: []byte(fmt.Sprintf(`{"gcpServiceAccount":"%v"}`, r.WorkloadIdentity)),
					},
				})
			}
		}
	}
	if err := r.Update(ctx, profileIns); err != nil {
		return err
	}
	return nil
}

// GetPluginSpec will try to unmarshal the plugin spec inside profile for the specified plugin
// Returns an error if the plugin isn't defined or if there is a problem
func (r *ProfileReconciler) GetPluginSpec(profileIns *icodeaiv1.Profile) ([]Plugin, error) {
	logger := r.Log.WithValues("profile", profileIns.Name)
	plugins := []Plugin{}
	for _, p := range profileIns.Spec.Plugins {
		var pluginIns Plugin
		switch p.Kind {
		case KIND_WORKLOAD_IDENTITY:
			pluginIns = &GcpWorkloadIdentity{}
		case KIND_AWS_IAM_FOR_SERVICE_ACCOUNT:
			pluginIns = &AwsIAMForServiceAccount{}
		default:
			logger.Info("Plugin not recgonized: ", "Kind", p.Kind)
			continue
		}

		// To deserialize it to a specific type we need to first serialize it to bytes
		// and then unserialize it.
		specBytes, err := yaml.Marshal(p.Spec)

		if err != nil {
			logger.Info("Could not marshal plugin ", p.Kind, "; error: ", err)
			return nil, err
		}

		err = yaml.Unmarshal(specBytes, pluginIns)
		if err != nil {
			logger.Info("Could not unmarshal plugin ", p.Kind, "; error: ", err)
			return nil, err
		}
		plugins = append(plugins, pluginIns)
	}
	return plugins, nil
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
