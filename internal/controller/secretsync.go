// Package controller reconciles SecretSync resources into Kubernetes Secrets.
package controller

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/rapatao/secret-manager/api/v1alpha1"
	"github.com/rapatao/secret-manager/internal/reload"
	"github.com/rapatao/secret-manager/internal/render"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
)

const (
	// Finalizer releases target Secrets before a SecretSync is removed.
	Finalizer = "secretmanager.rapatao.com/cleanup"
	// OwnerLabel holds a hash of the owning SecretSync namespace/name.
	OwnerLabel = "secretmanager.rapatao.com/owner"
	// OwnerAnnotation holds the owning SecretSync as namespace/name.
	OwnerAnnotation = "secretmanager.rapatao.com/owner"
	// PolicyLabel holds the CreationPolicy of a target Secret.
	PolicyLabel = "secretmanager.rapatao.com/creation-policy"
	// HashAnnotation holds the hash of a target Secret data.
	HashAnnotation = "secretmanager.rapatao.com/hash"

	defaultRefresh = time.Minute
)

// Changes carries paths changed through secrets.Service to the controller.
type Changes chan event.TypedGenericEvent[string]

// NewChanges returns a buffered Changes channel.
func NewChanges() Changes { return make(Changes, 1024) }

// Notify queues path without blocking. When the buffer is full the event is
// dropped and the periodic resync applies the change.
func (c Changes) Notify(path string) {
	select {
	case c <- event.TypedGenericEvent[string]{Object: path}:
	default:
	}
}

// SecretSyncReconciler writes target Secrets from secret-manager paths.
type SecretSyncReconciler struct {
	Client  client.Client
	Secrets *secrets.Service
	Changes Changes
}

// SetupWithManager registers the reconciler and its watches.
func (r *SecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SecretSync{}).
		WatchesRawSource(source.Channel(r.Changes, handler.TypedEnqueueRequestsFromMapFunc(r.RequestsForPath))).
		Complete(r)
}

// RequestsForPath returns the SecretSyncs reading path.
func (r *SecretSyncReconciler) RequestsForPath(ctx context.Context, path string) []reconcile.Request {
	var list v1alpha1.SecretSyncList
	if err := r.Client.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "listing SecretSyncs for changed path", "path", path)
		return nil
	}
	var reqs []reconcile.Request
	for _, ss := range list.Items {
		for _, src := range ss.Spec.Sources {
			srcPath, err := secrets.NormalizePath(src.Path)
			if err != nil {
				continue
			}
			if path == srcPath || (src.Recursive && storage.Under(path, srcPath)) {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ss)})
				break
			}
		}
	}
	return reqs
}

// Reconcile syncs every target of a SecretSync.
func (r *SecretSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ss v1alpha1.SecretSync
	if err := r.Client.Get(ctx, req.NamespacedName, &ss); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !ss.DeletionTimestamp.IsZero() {
		if err := r.release(ctx, &ss, nil); err != nil {
			return ctrl.Result{}, err
		}
		if controllerutil.RemoveFinalizer(&ss, Finalizer) {
			return ctrl.Result{}, r.Client.Update(ctx, &ss)
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&ss, Finalizer) {
		return ctrl.Result{}, r.Client.Update(ctx, &ss)
	}

	interval := defaultRefresh
	if ss.Spec.RefreshInterval != nil && ss.Spec.RefreshInterval.Duration > 0 {
		interval = ss.Spec.RefreshInterval.Duration
	}
	result := ctrl.Result{RequeueAfter: interval}

	values, err := r.resolve(ctx, &ss)
	if err != nil {
		return withStatus(result, r.setStatus(ctx, &ss, "", metav1.ConditionFalse, "SourceError", err.Error()))
	}

	keep := map[string]bool{}
	var failures []string
	for _, t := range ss.Spec.Targets {
		ns := cmp.Or(t.Namespace, ss.Namespace)
		keep[ns+"/"+t.Name] = true
		if err := r.syncTarget(ctx, &ss, t, ns, values); err != nil {
			failures = append(failures, fmt.Sprintf("%s/%s: %v", ns, t.Name, err))
		}
	}
	if err := r.release(ctx, &ss, keep); err != nil {
		failures = append(failures, err.Error())
	}

	hash := hashData(toBytes(values))
	if len(failures) > 0 {
		return withStatus(result, r.setStatus(ctx, &ss, hash, metav1.ConditionFalse, "SyncFailed", strings.Join(failures, "; ")))
	}
	return withStatus(result, r.setStatus(ctx, &ss, hash, metav1.ConditionTrue, "Synced", fmt.Sprintf("%d target(s) in sync", len(ss.Spec.Targets))))
}

// withStatus keeps the periodic requeue unless the status write failed, in
// which case the error triggers a retry with backoff.
func withStatus(result ctrl.Result, err error) (ctrl.Result, error) {
	if err != nil {
		return ctrl.Result{}, err
	}
	return result, nil
}

func (r *SecretSyncReconciler) resolve(ctx context.Context, ss *v1alpha1.SecretSync) (map[string]string, error) {
	values := map[string]string{}
	for _, src := range ss.Spec.Sources {
		data, err := r.Secrets.Get(ctx, src.Path, src.Recursive)
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, fmt.Errorf("source %s not found", src.Path)
		}
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", src.Path, err)
		}
		maps.Copy(values, data)
	}
	return values, nil
}

func (r *SecretSyncReconciler) syncTarget(ctx context.Context, ss *v1alpha1.SecretSync, t v1alpha1.Target, ns string, values map[string]string) error {
	var tmpl map[string]string
	if t.Template != nil {
		tmpl = t.Template.Data
	}
	data, err := render.Render(values, tmpl)
	if err != nil {
		return err
	}
	hash := hashData(data)
	owner := ownerKey(ss)

	labels := maps.Clone(t.Metadata.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[OwnerLabel] = hashOwner(owner)
	labels[PolicyLabel] = string(cmp.Or(t.CreationPolicy, v1alpha1.CreationPolicyOwner))

	annotations := maps.Clone(t.Metadata.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[OwnerAnnotation] = owner
	annotations[HashAnnotation] = hash

	var existing corev1.Secret
	err = r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: t.Name}, &existing)
	if apierrors.IsNotFound(err) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: t.Name, Labels: labels, Annotations: annotations},
			Type:       cmp.Or(t.Type, corev1.SecretTypeOpaque),
			Data:       data,
		}
		return r.Client.Create(ctx, s)
	}
	if err != nil {
		return err
	}

	if existing.Labels[OwnerLabel] != labels[OwnerLabel] {
		return errors.New("secret exists and is not managed by this SecretSync")
	}
	if existing.Type != cmp.Or(t.Type, corev1.SecretTypeOpaque) {
		return fmt.Errorf("secret type is %s and cannot change; delete the secret to recreate it", existing.Type)
	}

	changed := existing.Annotations[HashAnnotation] != hash
	if !changed &&
		maps.EqualFunc(existing.Data, data, bytes.Equal) &&
		maps.Equal(existing.Labels, labels) &&
		maps.Equal(existing.Annotations, annotations) {
		return nil
	}

	existing.Labels = labels
	existing.Annotations = annotations
	existing.Data = data
	if err := r.Client.Update(ctx, &existing); err != nil {
		return err
	}
	if !changed {
		return nil
	}
	restarted, err := reload.Deployments(ctx, r.Client, ns, t.Name, hash)
	if len(restarted) > 0 {
		log.FromContext(ctx).Info("restarted deployments", "namespace", ns, "secret", t.Name, "deployments", restarted)
	}
	return err
}

// release deletes Owner-policy Secrets of ss not listed in keep and detaches
// Orphan-policy ones. A nil keep releases every target.
func (r *SecretSyncReconciler) release(ctx context.Context, ss *v1alpha1.SecretSync, keep map[string]bool) error {
	var list corev1.SecretList
	if err := r.Client.List(ctx, &list, client.MatchingLabels{OwnerLabel: hashOwner(ownerKey(ss))}); err != nil {
		return fmt.Errorf("list owned secrets: %w", err)
	}
	for i := range list.Items {
		s := &list.Items[i]
		if keep[s.Namespace+"/"+s.Name] {
			continue
		}
		var err error
		if s.Labels[PolicyLabel] == string(v1alpha1.CreationPolicyOrphan) {
			delete(s.Labels, OwnerLabel)
			delete(s.Labels, PolicyLabel)
			delete(s.Annotations, OwnerAnnotation)
			delete(s.Annotations, HashAnnotation)
			err = r.Client.Update(ctx, s)
		} else {
			err = client.IgnoreNotFound(r.Client.Delete(ctx, s))
		}
		if err != nil {
			return fmt.Errorf("release %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	return nil
}

func (r *SecretSyncReconciler) setStatus(ctx context.Context, ss *v1alpha1.SecretSync, hash string, status metav1.ConditionStatus, reason, message string) error {
	next := ss.Status.DeepCopy()
	next.ObservedGeneration = ss.Generation
	if hash != "" {
		next.LastSyncedHash = hash
	}
	meta.SetStatusCondition(&next.Conditions, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ss.Generation,
	})
	if equality.Semantic.DeepEqual(ss.Status, *next) {
		return nil
	}
	patch := client.MergeFrom(ss.DeepCopy())
	ss.Status = *next
	return r.Client.Status().Patch(ctx, ss, patch)
}

func ownerKey(ss *v1alpha1.SecretSync) string { return ss.Namespace + "/" + ss.Name }

// hashOwner fits namespace/name into the 63 character label value limit.
func hashOwner(owner string) string {
	sum := sha256.Sum256([]byte(owner))
	return hex.EncodeToString(sum[:16])
}

func hashData(data map[string][]byte) string {
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintf(h, "%d:%s%d:", len(k), k, len(data[k]))
		h.Write(data[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func toBytes(values map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(values))
	for k, v := range values {
		out[k] = []byte(v)
	}
	return out
}
