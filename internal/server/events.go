package server

import (
	"fmt"
	"slices"
	"strings"
)

// Level is where the events of a category go.
type Level int

const (
	// LevelNone drops the events.
	LevelNone Level = iota
	// LevelLog writes the events to the log only.
	LevelLog
	// LevelAudit writes the events to the log and keeps them on the Audit
	// page and in the audit store.
	LevelAudit
)

var levelNames = []string{"none", "log", "audit"}

func (l Level) String() string { return levelNames[l] }

// Events sets the level of each category of audit events. Every event outside
// these categories is always audited.
type Events struct {
	// Reads are reads of secret values: read and read_version.
	Reads Level
	// Lists are reads without values: info, list_paths and list_history.
	Lists Level
	// Logins are Web UI sign-ins and CLI logins: login, authorize,
	// authorize_start and authorize_token.
	Logins Level
	// Backups are backup and restore.
	Backups Level
}

// DefaultEvents audits logins and backups and drops reads and lists.
var DefaultEvents = Events{Reads: LevelNone, Lists: LevelNone, Logins: LevelAudit, Backups: LevelAudit}

type category struct {
	name   string
	level  *Level
	noNone bool
}

func (e *Events) categories() []category {
	return []category{
		{"reads", &e.Reads, false},
		{"lists", &e.Lists, false},
		{"logins", &e.Logins, true},
		{"backups", &e.Backups, true},
	}
}

func (e Events) String() string {
	var parts []string
	for _, c := range e.categories() {
		parts = append(parts, c.name+"="+c.level.String())
	}
	return strings.Join(parts, ",")
}

// ParseEvents applies a comma separated list of category=level, such as
// "reads=audit,lists=log", to base.
func ParseEvents(base Events, s string) (Events, error) {
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		name, value, _ := strings.Cut(item, "=")
		cats := base.categories()
		i := slices.IndexFunc(cats, func(c category) bool { return c.name == name })
		if i < 0 {
			return base, fmt.Errorf("unknown event category %q: use reads, lists, logins or backups", name)
		}
		c := cats[i]
		l := Level(slices.Index(levelNames, value))
		if l < 0 || (c.noNone && l == LevelNone) {
			allowed := "none, log or audit"
			if c.noNone {
				allowed = "log or audit"
			}
			return base, fmt.Errorf("event category %s: level %q must be %s", name, value, allowed)
		}
		*c.level = l
	}
	return base, nil
}
