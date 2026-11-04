package server

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
)

const (
	recentChangesShown = 10
	expiringWithin     = 7 * 24 * time.Hour
)

type recentChange struct {
	Path    string
	Number  int
	Time    time.Time
	Changes []secrets.Change
}

type integrationStats struct {
	Total, Expired, Expiring, NeverUsed, FullAccess int
}

// shortDuration formats d without trailing zero units: 24h, not 24h0m0s.
func shortDuration(d time.Duration) string {
	out := d.String()
	if strings.HasSuffix(out, "m0s") {
		out = strings.TrimSuffix(out, "0s")
	}
	if strings.HasSuffix(out, "h0m") {
		out = strings.TrimSuffix(out, "0m")
	}
	return out
}

// uiSummary shows counts of the stored data and integrations, the latest
// changes and the server settings.
func (s *Server) uiSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	paths, err := s.secrets.ListPaths(ctx)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	deleted, err := s.secrets.DeletedPaths(ctx)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	// ponytail: reads every path and its history per view; add backend counters if stores reach thousands of paths.
	keys := 0
	for _, p := range paths {
		data, err := s.secrets.Get(ctx, p, false)
		if err != nil {
			s.uiError(w, r, err)
			return
		}
		keys += len(data)
	}
	var recent []recentChange
	for _, p := range slices.Concat(paths, deleted) {
		versions, err := s.secrets.History(ctx, p)
		if err != nil {
			s.uiError(w, r, err)
			return
		}
		for i, v := range versions {
			c := recentChange{Path: p, Number: v.Number, Time: v.Time}
			switch {
			case i+1 < len(versions):
				c.Changes = secrets.Diff(versions[i+1].Data, v.Data)
			case v.Number == 1:
				c.Changes = secrets.Diff(nil, v.Data)
			}
			recent = append(recent, c)
		}
	}
	versionCount := len(recent)
	slices.SortStableFunc(recent, func(a, b recentChange) int { return b.Time.Compare(a.Time) })
	recent = recent[:min(len(recent), recentChangesShown)]

	list, err := s.tokens.List(ctx)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	now := time.Now()
	stats := integrationStats{Total: len(list)}
	for _, t := range list {
		switch {
		case !t.Expires.IsZero() && !now.Before(t.Expires):
			stats.Expired++
		case !t.Expires.IsZero() && t.Expires.Sub(now) < expiringWithin:
			stats.Expiring++
		}
		if t.LastUsed.IsZero() {
			stats.NeverUsed++
		}
		if t.Path == "/" && !t.ReadOnly {
			stats.FullAccess++
		}
	}

	s.render(w, http.StatusOK, "summary", map[string]any{
		"Paths":        len(paths),
		"Deleted":      len(deleted),
		"Keys":         keys,
		"Versions":     versionCount,
		"Recent":       recent,
		"Integrations": stats,
		"Settings":     s.Settings,
		"HistoryLimit": s.secrets.KeepVersions,
		"CacheMaxAge":  cacheLabel(s.CacheMaxAge),
		"LastBackup":   s.lastBackup.Load(),
		"BackupEvery":  shortDuration(s.Settings.Backups.Interval),
	})
}
