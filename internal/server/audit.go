package server

import (
	"net/http"
	"slices"
	"sync"
	"time"
)

// auditKept is the number of audit events the Web UI shows.
const auditKept = 500

// auditEvent is one audit log entry. Token is the integration that made the
// request; Name is the integration an integration operation acted on.
type auditEvent struct {
	Time                                 time.Time
	Source, Op, Remote, Forwarded, Token string
	Path, Name, Error                    string
	Keys                                 []string
}

// auditLog keeps the newest audit events.
// ponytail: in memory, so it starts empty on restart and each replica has its
// own; the JSON audit log on stderr is the durable record.
type auditLog struct {
	mu     sync.Mutex
	events []auditEvent
}

func (l *auditLog) add(e auditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if len(l.events) > auditKept {
		l.events = slices.Clone(l.events[len(l.events)-auditKept:])
	}
}

// recent returns the kept events, newest first.
func (l *auditLog) recent() []auditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := slices.Clone(l.events)
	slices.Reverse(out)
	return out
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
	})
}
