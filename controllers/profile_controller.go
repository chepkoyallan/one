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
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	icodeaiv1 "github.com/chepkoy/one/api/v1"
	corev1 "k8s.io/api/core/v1"
)

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

	return ctrl.Result{}, nil
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
