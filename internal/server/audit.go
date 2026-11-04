package server

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
)

// auditKept is the number of audit events kept and shown in the Web UI.
const auditKept = 500

// AuditFlushInterval is how often RunAuditFlush saves new audit events.
const AuditFlushInterval = time.Minute

type auditEvent = storage.AuditEvent

// AuditStore persists the kept audit events.
type AuditStore interface {
	AuditEvents(ctx context.Context) ([]storage.AuditEvent, error)
	PutAuditEvents(ctx context.Context, events []storage.AuditEvent) error
}

// auditLog keeps the newest audit events.
type auditLog struct {
	mu     sync.Mutex
	events []auditEvent
	dirty  bool
}

func (l *auditLog) add(e auditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if len(l.events) > auditKept {
		l.events = slices.Clone(l.events[len(l.events)-auditKept:])
	}
	l.dirty = true
}

// recent returns the kept events, newest first.
func (l *auditLog) recent() []auditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := slices.Clone(l.events)
	slices.Reverse(out)
	return out
}

// LoadAudit reads the audit events saved in store, keeping events recorded
// since the server started after them, and makes store the target of
// FlushAudit.
func (s *Server) LoadAudit(ctx context.Context, store AuditStore) error {
	saved, err := store.AuditEvents(ctx)
	if err != nil {
		return err
	}
	l := &s.auditLog
	l.mu.Lock()
	defer l.mu.Unlock()
	s.auditStore = store
	l.events = slices.Concat(saved, l.events)
	l.events = l.events[max(len(l.events)-auditKept, 0):]
	return nil
}

// FlushAudit saves the kept audit events when some were recorded since the
// last save.
func (s *Server) FlushAudit(ctx context.Context) error {
	l := &s.auditLog
	l.mu.Lock()
	if s.auditStore == nil || !l.dirty {
		l.mu.Unlock()
		return nil
	}
	events := slices.Clone(l.events)
	l.dirty = false
	l.mu.Unlock()
	if err := s.auditStore.PutAuditEvents(ctx, events); err != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return err
	}
	return nil
}

// RunAuditFlush calls FlushAudit every interval and once more when ctx is
// done.
func (s *Server) RunAuditFlush(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.FlushAudit(flushCtx); err != nil {
				s.log.Warn("save audit events", "error", err)
			}
			return
		case <-t.C:
			if err := s.FlushAudit(ctx); err != nil {
				s.log.Warn("save audit events", "error", err)
			}
		}
	}
}

// uiAudit lists the kept audit events, newest first, optionally only those
// made by or acting on one integration.
func (s *Server) uiAudit(w http.ResponseWriter, r *http.Request) {
	events := s.auditLog.recent()
	var names []string
	for _, e := range events {
		for _, n := range []string{e.Token, e.Name} {
			if n != "" && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	filter := r.URL.Query().Get("integration")
	if filter != "" {
		events = slices.DeleteFunc(events, func(e auditEvent) bool { return e.Token != filter && e.Name != filter })
	}
	s.render(w, http.StatusOK, "audit", map[string]any{
		"Events":       events,
		"Integrations": names,
		"Filter":       filter,
		"Kept":         auditKept,
		"Saved":        s.auditStore != nil,
	})
}
