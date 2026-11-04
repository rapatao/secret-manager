package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/rapatao/secret-manager/internal/storage/encrypted"
)

type backupRun struct {
	Time      time.Time
	File, Err string
}

// BackupSchedule configures backups written by the server itself.
type BackupSchedule struct {
	// Dir receives one backup-<UTC time>.json file per run, mode 0600.
	Dir      string
	Interval time.Duration
	// Keep is the number of newest backup files kept in Dir.
	Keep    int
	History bool
	// Key, when set, encrypts every backup file; see encrypted.SealBackup.
	Key []byte
}

// RunBackups writes a backup to sched.Dir every sched.Interval until ctx is
// done. Failures are logged and retried on the next run.
func (s *Server) RunBackups(ctx context.Context, sched BackupSchedule) {
	t := time.NewTicker(sched.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			file, err := s.BackupToDir(ctx, sched)
			run := &backupRun{Time: time.Now(), File: file}
			if err != nil {
				run.Err = err.Error()
			}
			s.lastBackup.Store(run)
			e := auditEvent{Source: "schedule", Op: "backup"}
			if err != nil {
				e.Error = err.Error()
				s.record(s.Events.Backups, e)
				continue
			}
			s.record(s.Events.Backups, e, "file", file)
		}
	}
}

// BackupToDir writes one backup file to sched.Dir, then removes all but the
// newest sched.Keep backup files. It returns the path of the new file.
func (s *Server) BackupToDir(ctx context.Context, sched BackupSchedule) (string, error) {
	doc, err := s.backup(ctx, sched.History)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	if sched.Key != nil {
		if raw, err = encrypted.SealBackup(sched.Key, raw); err != nil {
			return "", err
		}
	}
	name := filepath.Join(sched.Dir, "backup-"+doc.Time.Format("20060102T150405Z")+".json")
	if err := writeFileAtomic(name, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}

	old, err := filepath.Glob(filepath.Join(sched.Dir, "backup-*.json"))
	if err != nil {
		return name, err
	}
	slices.Sort(old)
	for _, f := range old[:max(len(old)-sched.Keep, 0)] {
		if err := os.Remove(f); err != nil {
			return name, fmt.Errorf("prune %s: %w", f, err)
		}
	}
	return name, nil
}

func writeFileAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".backup-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
