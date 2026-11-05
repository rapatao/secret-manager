package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage/encrypted"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/tokens"
)

func TestBackupToDir(t *testing.T) {
	ctx := context.Background()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	svc := secrets.New(backend, nil)
	svc.KeepVersions = 10
	if err := svc.SetKeys(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	s, err := New(svc, tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, old := range []string{"backup-20200101T000000Z.json", "backup-20200102T000000Z.json", "other.json"} {
		if err := os.WriteFile(filepath.Join(dir, old), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	file, err := s.BackupToDir(ctx, BackupSchedule{Dir: dir, Interval: time.Hour, Keep: 2, History: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup file %s: %v %v", file, info, err)
	}
	var doc backupJSON
	raw, _ := os.ReadFile(file)
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Paths) != 1 || len(doc.Paths[0].Versions) != 1 {
		t.Fatalf("backup document %s: %v", raw, err)
	}

	sealed, err := s.BackupToDir(ctx, BackupSchedule{Dir: t.TempDir(), Interval: time.Hour, Keep: 1, Passphrase: "schedule-pw"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(sealed)
	if !encrypted.IsEncryptedBackup(raw) {
		t.Fatalf("backup with a key not encrypted: %s", raw)
	}
	if plain, err := encrypted.OpenBackup("schedule-pw", raw); err != nil || json.Unmarshal(plain, &doc) != nil || len(doc.Paths) != 1 {
		t.Fatalf("encrypted backup %s: %v", plain, err)
	}

	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if got, want := strings.Join(names, ","), "backup-20200102T000000Z.json,"+filepath.Base(file)+",other.json"; got != want {
		t.Fatalf("files %s, want %s", got, want)
	}
}
