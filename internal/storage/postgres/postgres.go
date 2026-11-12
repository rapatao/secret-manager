// Package postgres stores secrets, their versions, integration tokens and audit
// events in PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rapatao/secret-manager/internal/storage"
)

// Advisory lock class ids, so locks taken here do not collide with other
// users of the same database.
const (
	lockSchema   = 0x736d0001
	lockVersions = 0x736d0002
)

// ponytail: tables are created when missing, no migration history; add a
// schema_version table with the first change to an existing table.
const schema = `
CREATE TABLE IF NOT EXISTS sm_paths (
	path text PRIMARY KEY,
	data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS sm_versions (
	path   text NOT NULL,
	number integer NOT NULL,
	time   timestamptz NOT NULL,
	data   jsonb NOT NULL,
	PRIMARY KEY (path, number)
);
CREATE TABLE IF NOT EXISTS sm_tokens (
	position integer PRIMARY KEY,
	doc      jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS sm_audit (
	position integer PRIMARY KEY,
	doc      jsonb NOT NULL
);
`

// Backend implements storage.Backend on top of PostgreSQL. Every call reads
// and writes the database, nothing is cached.
type Backend struct {
	pool *pgxpool.Pool
}

var _ storage.Backend = (*Backend)(nil)

// New connects to the database at url and creates the tables it needs when
// missing. url is a PostgreSQL connection URL or keyword/value string; an
// empty url uses the PG* environment variables.
func New(ctx context.Context, url string) (*Backend, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	b := &Backend{pool: pool}
	if err := b.createTables(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return b, nil
}

// Close closes every connection to the database.
func (b *Backend) Close() {
	b.pool.Close()
}

// createTables runs under a lock: concurrent CREATE TABLE IF NOT EXISTS of the
// same table can fail.
func (b *Backend) createTables(ctx context.Context) error {
	return pgx.BeginFunc(ctx, b.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockSchema)); err != nil {
			return fmt.Errorf("lock schema: %w", err)
		}
		if _, err := tx.Exec(ctx, schema); err != nil {
			return fmt.Errorf("create tables: %w", err)
		}
		return nil
	})
}

// Get implements storage.Backend.
func (b *Backend) Get(ctx context.Context, path string) (map[string]string, error) {
	var data map[string]string
	err := b.pool.QueryRow(ctx, `SELECT data FROM sm_paths WHERE path = $1`, path).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", path, err)
	}
	return data, nil
}

// Put implements storage.Backend.
func (b *Backend) Put(ctx context.Context, path string, data map[string]string) error {
	if data == nil {
		data = map[string]string{}
	}
	_, err := b.pool.Exec(ctx, `INSERT INTO sm_paths (path, data) VALUES ($1, $2)
		ON CONFLICT (path) DO UPDATE SET data = EXCLUDED.data`, path, data)
	if err != nil {
		return fmt.Errorf("put %s: %w", path, err)
	}
	return nil
}

// Delete implements storage.Backend.
func (b *Backend) Delete(ctx context.Context, path string) error {
	if _, err := b.pool.Exec(ctx, `DELETE FROM sm_paths WHERE path = $1`, path); err != nil {
		return fmt.Errorf("delete %s: %w", path, err)
	}
	return nil
}

// List implements storage.Backend.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	rows, _ := b.pool.Query(ctx, `SELECT path FROM sm_paths
		WHERE $1 = '/' OR path = $1 OR starts_with(path, $1 || '/')`, prefix)
	paths, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", prefix, err)
	}
	slices.Sort(paths)
	return paths, nil
}

// AddVersion implements storage.Backend.
func (b *Backend) AddVersion(ctx context.Context, path string, at time.Time, data map[string]string, keep int) error {
	return b.inVersionsTx(ctx, path, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(number), 0) + 1 FROM sm_versions WHERE path = $1`, path).Scan(&n); err != nil {
			return err
		}
		if data == nil {
			data = map[string]string{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sm_versions (path, number, time, data) VALUES ($1, $2, $3, $4)`, path, n, at, data); err != nil {
			return fmt.Errorf("add version %d: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sm_versions WHERE path = $1 AND number <= $2`, path, n-keep); err != nil {
			return fmt.Errorf("prune versions: %w", err)
		}
		return nil
	})
}

// Versions implements storage.Backend.
func (b *Backend) Versions(ctx context.Context, path string) ([]storage.Version, error) {
	rows, _ := b.pool.Query(ctx, `SELECT number, time, data FROM sm_versions WHERE path = $1 ORDER BY number DESC`, path)
	versions, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (storage.Version, error) {
		var v storage.Version
		err := row.Scan(&v.Number, &v.Time, &v.Data)
		return v, err
	})
	if err != nil {
		return nil, fmt.Errorf("versions of %s: %w", path, err)
	}
	return versions, nil
}

// VersionedPaths implements storage.Backend.
func (b *Backend) VersionedPaths(ctx context.Context) ([]string, error) {
	rows, _ := b.pool.Query(ctx, `SELECT DISTINCT path FROM sm_versions`)
	paths, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("versioned paths: %w", err)
	}
	slices.Sort(paths)
	return paths, nil
}

// ReplaceVersions implements storage.Backend.
func (b *Backend) ReplaceVersions(ctx context.Context, path string, versions []storage.Version) error {
	return b.inVersionsTx(ctx, path, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sm_versions WHERE path = $1`, path); err != nil {
			return err
		}
		for _, v := range versions {
			data := v.Data
			if data == nil {
				data = map[string]string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sm_versions (path, number, time, data) VALUES ($1, $2, $3, $4)`, path, v.Number, v.Time, data); err != nil {
				return fmt.Errorf("version %d: %w", v.Number, err)
			}
		}
		return nil
	})
}

// inVersionsTx runs fn in a transaction holding a lock on the versions of
// path, so concurrent writers never pick the same version number.
func (b *Backend) inVersionsTx(ctx context.Context, path string, fn func(pgx.Tx) error) error {
	err := pgx.BeginFunc(ctx, b.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, int32(lockVersions), path); err != nil {
			return err
		}
		return fn(tx)
	})
	if err != nil {
		return fmt.Errorf("versions of %s: %w", path, err)
	}
	return nil
}

// Tokens implements storage.Backend.
func (b *Backend) Tokens(ctx context.Context) ([]storage.Token, error) {
	rows, _ := b.pool.Query(ctx, `SELECT doc FROM sm_tokens ORDER BY position`)
	tokens, err := pgx.CollectRows(rows, pgx.RowTo[storage.Token])
	if err != nil {
		return nil, fmt.Errorf("tokens: %w", err)
	}
	return tokens, nil
}

// PutTokens implements storage.Backend.
func (b *Backend) PutTokens(ctx context.Context, tokens []storage.Token) error {
	if err := replaceDocs(ctx, b.pool, "sm_tokens", tokens); err != nil {
		return fmt.Errorf("put tokens: %w", err)
	}
	return nil
}

// AuditEvents implements storage.Backend.
func (b *Backend) AuditEvents(ctx context.Context) ([]storage.AuditEvent, error) {
	rows, _ := b.pool.Query(ctx, `SELECT doc FROM sm_audit ORDER BY position`)
	events, err := pgx.CollectRows(rows, pgx.RowTo[storage.AuditEvent])
	if err != nil {
		return nil, fmt.Errorf("audit events: %w", err)
	}
	return events, nil
}

// PutAuditEvents implements storage.Backend.
func (b *Backend) PutAuditEvents(ctx context.Context, events []storage.AuditEvent) error {
	if err := replaceDocs(ctx, b.pool, "sm_audit", events); err != nil {
		return fmt.Errorf("put audit events: %w", err)
	}
	return nil
}

// replaceDocs replaces every row of table with docs, kept in order.
func replaceDocs[T any](ctx context.Context, pool *pgxpool.Pool, table string, docs []T) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE `+table); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+table); err != nil {
			return err
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{table}, []string{"position", "doc"},
			pgx.CopyFromSlice(len(docs), func(i int) ([]any, error) { return []any{i, docs[i]}, nil }))
		return err
	})
}
