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
	"k8s.io/client-go/tools/events"
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
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
)

const (
	// Finalizer releases target Secrets before a SecretSync is removed.
	Finalizer = "secretmanager.rapatao.com/cleanup"
	// OwnerLabel holds a hash of the owning SecretSync namespace/name.
	OwnerLabel = k8sstorage.SyncOwnerLabel
	// OwnerAnnotation holds the owning SecretSync as namespace/name.
	OwnerAnnotation = "secretmanager.rapatao.com/owner"
	// PolicyLabel holds the CreationPolicy of a target Secret.
	PolicyLabel = "secretmanager.rapatao.com/creation-policy"
	// HashAnnotation holds the hash of a target Secret data.
	HashAnnotation = "secretmanager.rapatao.com/hash"

	// reservedPrefix starts every label and annotation key the server and the
	// controller set. Targets cannot carry such keys.
	reservedPrefix = "secretmanager.rapatao.com/"

	defaultRefresh = time.Minute
	maxRefresh     = time.Hour
)

// Changes carries paths changed through secrets.Service to the controller,
// and requests to reconcile every SecretSync on a channel of its own so a full
// path queue cannot drop them.
type Changes struct {
	paths chan event.TypedGenericEvent[string]
	all   chan event.TypedGenericEvent[string]
}

// NewChanges returns a buffered Changes.
func NewChanges() Changes {
	return Changes{
		paths: make(chan event.TypedGenericEvent[string], 1024),
		all:   make(chan event.TypedGenericEvent[string], 1),
	}
}

// Notify queues path without blocking. When the buffer is full the event is
// dropped and the periodic resync applies the change.
func (c Changes) Notify(path string) {
	select {
	case c.paths <- event.TypedGenericEvent[string]{Object: path}:
	default:
	}
}

// NotifyAll queues every SecretSync without blocking. A broadcast already
// waiting covers this one, as the policy is read when a SecretSync reconciles.
func (c Changes) NotifyAll() {
	select {
	case c.all <- event.TypedGenericEvent[string]{}:
	default:
	}
}

// SecretSyncReconciler writes target Secrets from secret-manager paths.
type SecretSyncReconciler struct {
	Client   client.Client
	Secrets  *secrets.Service
	Changes  Changes
	Recorder events.EventRecorder
	// Policy limits what SecretSyncs may read and write. Nil means unrestricted.
	Policy *syncpolicy.Store
	// StorageNamespace is the namespace of the kubernetes storage, empty for
	// other backends. Targets there cannot take names the server stores under.
	StorageNamespace string
}

// SetupWithManager registers the reconciler and its watches.
func (r *SecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SecretSync{}).
		WatchesRawSource(source.Channel(r.Changes.paths, handler.TypedEnqueueRequestsFromMapFunc(r.RequestsForPath))).
		WatchesRawSource(source.Channel(r.Changes.all, handler.TypedEnqueueRequestsFromMapFunc(r.RequestsForPath))).
		Complete(r)
}

// policyRetry is how long RequestsForPath waits before broadcasting again
// after it failed to list the SecretSyncs.
var policyRetry = 5 * time.Second

// RequestsForPath returns the SecretSyncs reading path, or every SecretSync
// for the empty path. When it cannot list them for the empty path, it
// broadcasts again after policyRetry.
func (r *SecretSyncReconciler) RequestsForPath(ctx context.Context, path string) []reconcile.Request {
	var list v1alpha1.SecretSyncList
	if err := r.Client.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "listing SecretSyncs for changed path", "path", path)
		if path == "" {
			time.AfterFunc(policyRetry, r.Changes.NotifyAll)
		}
		return nil
	}
	var reqs []reconcile.Request
	for _, ss := range list.Items {
		if path == "" {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ss)})
			continue
		}
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
		if err := r.release(ctx, &ss, nil, false); err != nil {
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
	result := ctrl.Result{RequeueAfter: min(interval, maxRefresh)}

	if r.Policy != nil {
		policy, err := r.Policy.Get(ctx)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("load sync policy: %w", err)
		}
		if err := checkPolicy(policy, &ss); errors.Is(err, syncpolicy.ErrDenied) {
			rerr := r.release(ctx, &ss, nil, true)
			ferr := r.fail(ctx, &ss, "", "NotAllowed", err.Error())
			if err := errors.Join(rerr, ferr); err != nil {
				return ctrl.Result{}, err
			}
			return result, nil
		} else if err != nil {
			return ctrl.Result{}, err
		}
	}

	values, err := r.resolve(ctx, &ss)
	if err != nil {
		return withStatus(result, r.fail(ctx, &ss, "", "SourceError", err.Error()))
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
	if err := r.release(ctx, &ss, keep, false); err != nil {
		failures = append(failures, err.Error())
	}

	hash := hashData(toBytes(values))
	if len(failures) > 0 {
		return withStatus(result, r.fail(ctx, &ss, hash, "SyncFailed", strings.Join(failures, "; ")))
	}
	return withStatus(result, r.setStatus(ctx, &ss, hash, metav1.ConditionTrue, "Synced", fmt.Sprintf("%d target(s) in sync", len(ss.Spec.Targets))))
}

// checkPolicy checks the sources and target namespaces of ss against policy.
func checkPolicy(policy storage.SyncPolicy, ss *v1alpha1.SecretSync) error {
	var sources []syncpolicy.SourceRef
	for _, src := range ss.Spec.Sources {
		sources = append(sources, syncpolicy.SourceRef{Path: src.Path, Recursive: src.Recursive})
	}
	var targetNamespaces []string
	for _, t := range ss.Spec.Targets {
		targetNamespaces = append(targetNamespaces, cmp.Or(t.Namespace, ss.Namespace))
	}
	return syncpolicy.Check(policy, ss.Namespace, sources, targetNamespaces)
}

// PolicyPreview returns a function listing, as "namespace/name: reason", the
// SecretSyncs that policy would disallow.
func PolicyPreview(c client.Client) func(context.Context, storage.SyncPolicy) ([]string, error) {
	return func(ctx context.Context, policy storage.SyncPolicy) ([]string, error) {
		var list v1alpha1.SecretSyncList
		if err := c.List(ctx, &list); err != nil {
			return nil, err
		}
		var denied []string
		for i := range list.Items {
			ss := &list.Items[i]
			if !ss.DeletionTimestamp.IsZero() {
				continue
			}
			if err := checkPolicy(policy, ss); errors.Is(err, syncpolicy.ErrDenied) {
				denied = append(denied, ownerKey(ss)+": "+err.Error())
			} else if err != nil {
				return nil, err
			}
		}
		slices.Sort(denied)
		return denied, nil
	}
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

// allowedTypes are the Secret types a target may have, besides the empty type,
// which means Opaque.
var allowedTypes = []corev1.SecretType{
	corev1.SecretTypeOpaque,
	corev1.SecretTypeDockerConfigJson,
	corev1.SecretTypeTLS,
	corev1.SecretTypeBasicAuth,
	corev1.SecretTypeSSHAuth,
}

// checkTarget rejects a target type, metadata and name the controller must not
// write.
func (r *SecretSyncReconciler) checkTarget(t v1alpha1.Target, ns string) error {
	if t.Type != "" && !slices.Contains(allowedTypes, t.Type) {
		allowed := make([]string, len(allowedTypes))
		for i, a := range allowedTypes {
			allowed[i] = string(a)
		}
		return fmt.Errorf("secret type %s is not allowed; use one of %s", t.Type, strings.Join(allowed, ", "))
	}
	var keys []string
	for _, m := range []map[string]string{t.Metadata.Labels, t.Metadata.Annotations} {
		for k := range m {
			if strings.HasPrefix(k, reservedPrefix) {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		return fmt.Errorf("metadata keys under %s are reserved: %s", reservedPrefix, strings.Join(slices.Compact(keys), ", "))
	}
	if r.reservedTarget(ns, t.Name) {
		return fmt.Errorf("the name %s is reserved for the server's storage in namespace %s", t.Name, ns)
	}
	return nil
}

func (r *SecretSyncReconciler) syncTarget(ctx context.Context, ss *v1alpha1.SecretSync, t v1alpha1.Target, ns string, values map[string]string) error {
	if err := r.checkTarget(t, ns); err != nil {
		return err
	}
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
		if err := r.Client.Create(ctx, s); err != nil {
			return err
		}
		r.Recorder.Eventf(ss, nil, corev1.EventTypeNormal, "Synced", "CreateSecret", "Created Secret %s/%s", ns, t.Name)
		return nil
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

	// The stored hash advances only after the restart succeeded, so a failed
	// restart is retried on the next resync.
	hashChanged := existing.Annotations[HashAnnotation] != hash
	dataChanged := !maps.EqualFunc(existing.Data, data, bytes.Equal)
	changed := hashChanged || dataChanged
	if hashChanged {
		if prev, ok := existing.Annotations[HashAnnotation]; ok {
			annotations[HashAnnotation] = prev
		} else {
			delete(annotations, HashAnnotation)
		}
	}
	if dataChanged || !maps.Equal(existing.Labels, labels) || !maps.Equal(existing.Annotations, annotations) {
		existing.Labels = labels
		existing.Annotations = annotations
		existing.Data = data
		if err := r.Client.Update(ctx, &existing); err != nil {
			return err
		}
		r.Recorder.Eventf(ss, nil, corev1.EventTypeNormal, "Synced", "UpdateSecret", "Updated Secret %s/%s", ns, t.Name)
	}
	if !changed {
		return nil
	}
	restarted, err := reload.Workloads(ctx, r.Client, ns, t.Name, hash)
	if len(restarted) > 0 {
		for _, w := range restarted {
			kind, _, _ := strings.Cut(w, "/")
			workloadRestarts.WithLabelValues(kind).Inc()
		}
		log.FromContext(ctx).Info("restarted workloads", "namespace", ns, "secret", t.Name, "workloads", restarted)
		r.Recorder.Eventf(ss, nil, corev1.EventTypeNormal, "WorkloadsRestarted", "RestartWorkloads",
			"Restarted %s in %s for Secret %s", strings.Join(restarted, ", "), ns, t.Name)
	}
	if err != nil {
		return err
	}
	if !hashChanged {
		return nil
	}
	existing.Annotations[HashAnnotation] = hash
	return r.Client.Update(ctx, &existing)
}

// reservedTarget reports whether a Secret called name in ns is one the server
// stores under.
func (r *SecretSyncReconciler) reservedTarget(ns, name string) bool {
	return r.StorageNamespace != "" && ns == r.StorageNamespace && k8sstorage.ReservedName(name)
}

// release deletes Owner-policy Secrets of ss not listed in keep and detaches
// Orphan-policy ones, except those named like the server's own Secrets, which
// are deleted. A nil keep releases every target. With force, Orphan Secrets
// are deleted too and every owned Secret is attempted, the failures joined.
// Without force the first failure stops the release.
func (r *SecretSyncReconciler) release(ctx context.Context, ss *v1alpha1.SecretSync, keep map[string]bool, force bool) error {
	var list corev1.SecretList
	if err := r.Client.List(ctx, &list, client.MatchingLabels{OwnerLabel: hashOwner(ownerKey(ss))}); err != nil {
		return fmt.Errorf("list owned secrets: %w", err)
	}
	var errs []error
	for i := range list.Items {
		s := &list.Items[i]
		if keep[s.Namespace+"/"+s.Name] || s.Annotations[OwnerAnnotation] != ownerKey(ss) {
			continue
		}
		var err error
		reserved := r.reservedTarget(s.Namespace, s.Name)
		switch {
		case force:
			err = r.Client.Delete(ctx, s, client.Preconditions{UID: &s.UID})
			if apierrors.IsNotFound(err) {
				err = nil
			} else if err == nil {
				log.FromContext(ctx).Info("deleted Secret of a SecretSync not allowed by the sync policy", "secret", s.Namespace+"/"+s.Name, "owner", ownerKey(ss))
				r.Recorder.Eventf(ss, nil, corev1.EventTypeWarning, "Released", "DeleteSecret", "Deleted Secret %s/%s: SecretSync not allowed", s.Namespace, s.Name)
			}
		case s.Labels[PolicyLabel] == string(v1alpha1.CreationPolicyOrphan) && !reserved:
			s.Labels = withoutReserved(s.Labels)
			s.Annotations = withoutReserved(s.Annotations)
			err = r.Client.Update(ctx, s)
		default:
			err = r.Client.Delete(ctx, s, client.Preconditions{UID: &s.UID})
			if apierrors.IsNotFound(err) {
				err = nil
			} else if err == nil && reserved && s.Labels[PolicyLabel] == string(v1alpha1.CreationPolicyOrphan) {
				log.FromContext(ctx).Info("deleted Orphan Secret named like a server Secret", "secret", s.Namespace+"/"+s.Name, "owner", ownerKey(ss))
				r.Recorder.Eventf(ss, nil, corev1.EventTypeWarning, "Released", "DeleteSecret", "Deleted Secret %s/%s: name reserved for the server's storage", s.Namespace, s.Name)
			}
		}
		if err != nil {
			if !force {
				return fmt.Errorf("release %s/%s: %w", s.Namespace, s.Name, err)
			}
			errs = append(errs, fmt.Errorf("release %s/%s: %w", s.Namespace, s.Name, err))
		}
	}
	return errors.Join(errs...)
}

// withoutReserved returns m without the keys under reservedPrefix.
func withoutReserved(m map[string]string) map[string]string {
	out := maps.Clone(m)
	maps.DeleteFunc(out, func(k, _ string) bool { return strings.HasPrefix(k, reservedPrefix) })
	return out
}

// fail counts a failed sync and sets Ready to False.
func (r *SecretSyncReconciler) fail(ctx context.Context, ss *v1alpha1.SecretSync, hash, reason, message string) error {
	syncFailures.WithLabelValues(reason).Inc()
	return r.setStatus(ctx, ss, hash, metav1.ConditionFalse, reason, message)
}

// setStatus writes the Ready condition. A new failure reason or message emits
// a Warning event once instead of on every resync.
func (r *SecretSyncReconciler) setStatus(ctx context.Context, ss *v1alpha1.SecretSync, hash string, status metav1.ConditionStatus, reason, message string) error {
	if prev := meta.FindStatusCondition(ss.Status.Conditions, v1alpha1.ConditionReady); status == metav1.ConditionFalse &&
		(prev == nil || prev.Reason != reason || prev.Message != message) {
		r.Recorder.Eventf(ss, nil, corev1.EventTypeWarning, reason, "Sync", "%s", message)
	}
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
