package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
)

// policyRow is a namespace of the policy as the form shows it.
type policyRow struct {
	Namespace, Paths, Targets string
}

func policyRows(p storage.SyncPolicy) []policyRow {
	var rows []policyRow
	for _, ns := range slices.Sorted(maps.Keys(p.Namespaces)) {
		rule := p.Namespaces[ns]
		rows = append(rows, policyRow{ns, strings.Join(rule.Paths, "\n"), strings.Join(rule.TargetNamespaces, " ")})
	}
	return append(rows, policyRow{})
}

func (s *Server) renderPolicy(w http.ResponseWriter, r *http.Request, status int, p storage.SyncPolicy, denied []string, digest, base string) {
	s.render(w, status, "syncpolicy", map[string]any{
		"Digest":     digest,
		"Base":       base,
		"Enabled":    p.Enabled,
		"Rows":       policyRows(p),
		"Controller": s.Settings.Controller,
		"Denied":     denied,
		"Error":      r.URL.Query().Get("error"),
	})
}

func (s *Server) uiSyncPolicy(w http.ResponseWriter, r *http.Request) {
	if s.SyncPolicy == nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.SyncPolicy.Get(r.Context())
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	s.renderPolicy(w, r, http.StatusOK, p, nil, "", baseDigest(p))
}

// parsePolicy reads the policy form. Rows with nothing in them are skipped.
func parsePolicy(r *http.Request) (storage.SyncPolicy, error) {
	namespaces, paths, targets := r.PostForm["namespace"], r.PostForm["paths"], r.PostForm["targets"]
	if len(namespaces) == 0 || len(namespaces) != len(paths) || len(namespaces) != len(targets) {
		return storage.SyncPolicy{}, fmt.Errorf("%w: malformed policy form", secrets.ErrInvalid)
	}
	removed := map[string]bool{}
	for _, i := range r.PostForm["remove"] {
		removed[i] = true
	}
	p := storage.SyncPolicy{Enabled: r.PostFormValue("enabled") == "true", Namespaces: map[string]storage.SyncRule{}}
	for i, ns := range namespaces {
		ns = strings.TrimSpace(ns)
		rule := storage.SyncRule{Paths: strings.Fields(paths[i]), TargetNamespaces: strings.Fields(targets[i])}
		if removed[strconv.Itoa(i)] || (ns == "" && len(rule.Paths) == 0 && len(rule.TargetNamespaces) == 0) {
			continue
		}
		if _, dup := p.Namespaces[ns]; dup {
			return storage.SyncPolicy{}, fmt.Errorf("%w: namespace %q is listed twice", secrets.ErrInvalid, ns)
		}
		p.Namespaces[ns] = rule
	}
	return p, nil
}

// newlyDenied lists the SecretSyncs p disallows that the stored policy old
// does not already disallow.
func (s *Server) newlyDenied(r *http.Request, old, p storage.SyncPolicy) ([]string, error) {
	denied, err := s.PolicyPreview(r.Context(), p)
	if err != nil {
		return nil, err
	}
	if old.Enabled && len(denied) > 0 {
		already, err := s.PolicyPreview(r.Context(), old)
		if err != nil {
			return nil, err
		}
		denied = slices.DeleteFunc(slices.Clone(denied), func(d string) bool { return slices.Contains(already, d) })
	}
	denied = slices.Clone(denied)
	slices.Sort(denied)
	return slices.Compact(denied), nil
}

// policyDigest binds a confirmation to the policy and the list shown with it.
func policyDigest(p storage.SyncPolicy, denied []string) string {
	if denied == nil {
		denied = []string{}
	}
	doc, _ := json.Marshal(struct {
		Policy storage.SyncPolicy
		Denied []string
	}{p, denied})
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}

func (s *Server) uiSaveSyncPolicy(w http.ResponseWriter, r *http.Request) {
	if s.SyncPolicy == nil {
		http.NotFound(w, r)
		return
	}
	fail := func(err error) { s.redirectWithError(w, r, "/sync-policy?", err) }
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err := r.ParseForm()
	if err != nil {
		err = fmt.Errorf("%w: %w", secrets.ErrInvalid, err)
	}
	var p storage.SyncPolicy
	if err == nil {
		p, err = parsePolicy(r)
	}
	if err == nil {
		p, err = syncpolicy.Validate(p)
	}
	if err != nil {
		fail(err)
		return
	}
	conflict := func() {
		msg := syncpolicy.ErrConflict.Error() + "; the current policy is shown, review it and save again"
		http.Redirect(w, r, "/sync-policy?error="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	old, err := s.SyncPolicy.Get(r.Context())
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	base := r.PostFormValue("base")
	if base != baseDigest(old) {
		s.auditPolicy(r, "ui", old, p, syncpolicy.ErrConflict)
		conflict()
		return
	}
	if p.Enabled && s.PolicyPreview != nil {
		denied, err := s.newlyDenied(r, old, p)
		if err != nil {
			s.uiError(w, r, err)
			return
		}
		digest := policyDigest(p, denied)
		if len(denied) > 0 && (r.PostFormValue("confirm") != "delete" || r.PostFormValue("digest") != digest) {
			s.renderPolicy(w, r, http.StatusOK, p, denied, digest, base)
			return
		}
	}
	err = s.putSyncPolicy(r, "ui", old, p)
	if errors.Is(err, syncpolicy.ErrConflict) {
		conflict()
		return
	}
	if err != nil {
		fail(err)
		return
	}
	http.Redirect(w, r, "/sync-policy", http.StatusSeeOther)
}

// PolicyDigestHeader carries the digest of the stored sync policy in the
// responses of GET and PUT /api/v1/sync-policy.
const PolicyDigestHeader = "X-Sync-Policy-Digest"

// baseDigest identifies the stored policy p. A save names the digest it read
// as its base and is refused when the stored policy has another.
func baseDigest(p storage.SyncPolicy) string { return policyDigest(p, nil) }

// putSyncPolicy stores p over old, which must still be the stored policy, and
// audits the change.
func (s *Server) putSyncPolicy(r *http.Request, source string, old, p storage.SyncPolicy) error {
	_, err := s.SyncPolicy.Put(r.Context(), old, p)
	s.auditPolicy(r, source, old, p, err)
	return err
}

// auditPolicy audits the change from old to p, which failed with err when it
// is not nil.
func (s *Server) auditPolicy(r *http.Request, source string, old, p storage.SyncPolicy, err error) {
	op := "update_sync_policy"
	switch {
	case !old.Enabled && p.Enabled:
		op = "enable_sync_policy"
	case old.Enabled && !p.Enabled:
		op = "disable_sync_policy"
	}
	s.audit(r, source, op, "", slices.Sorted(maps.Keys(p.Namespaces)), err)
}

func (s *Server) apiGetSyncPolicy(w http.ResponseWriter, r *http.Request) {
	if s.SyncPolicy == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	p, err := s.SyncPolicy.Get(r.Context())
	s.auditAt(s.Events.Lists, r, "api", "get_sync_policy", "", nil, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.Header().Set(PolicyDigestHeader, baseDigest(p))
	writeJSON(w, http.StatusOK, p)
}

// apiPutSyncPolicy replaces the policy the request names with ?base, the
// digest GET returned. When the new policy disallows SecretSyncs the stored
// one does not, the answer is a 409 listing them with the digest of this
// preview, and the save needs ?confirm set to that digest.
func (s *Server) apiPutSyncPolicy(w http.ResponseWriter, r *http.Request) {
	if s.SyncPolicy == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	base := r.URL.Query().Get("base")
	if base == "" {
		writeError(w, http.StatusBadRequest, "base is required: send the "+PolicyDigestHeader+" header of GET /api/v1/sync-policy as ?base=")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	var p storage.SyncPolicy
	if err := dec.Decode(&p); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "body must be a sync policy document")
		return
	}
	p, err := syncpolicy.Validate(p)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	old, err := s.SyncPolicy.Get(r.Context())
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	if baseDigest(old) != base {
		s.auditPolicy(r, "api", old, p, syncpolicy.ErrConflict)
		writeError(w, http.StatusConflict, syncpolicy.ErrConflict.Error()+"; read it again")
		return
	}
	if p.Enabled && s.PolicyPreview != nil {
		denied, err := s.newlyDenied(r, old, p)
		if err != nil {
			s.serviceError(w, r, err)
			return
		}
		digest := policyDigest(p, denied)
		if len(denied) > 0 && r.URL.Query().Get("confirm") != digest {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":  fmt.Sprintf("the policy disallows %d SecretSyncs, which lose their target Secrets; repeat with confirm=%s to save it", len(denied), digest),
				"denied": denied,
				"count":  len(denied),
				"digest": digest,
			})
			return
		}
	}
	if err := s.putSyncPolicy(r, "api", old, p); errors.Is(err, syncpolicy.ErrConflict) {
		writeError(w, http.StatusConflict, err.Error()+"; read it again")
		return
	} else if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.Header().Set(PolicyDigestHeader, baseDigest(p))
	writeJSON(w, http.StatusOK, p)
}
