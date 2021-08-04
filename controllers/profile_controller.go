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

	icodeaiv1 "github.com/chepkoy/one/api/v1"
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
	//if err = r.updateSer

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
