package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

// envTestDatabase names a PostgreSQL connection URL the tests may create and
// drop schemas in. The tests are skipped when it is unset.
const envTestDatabase = "SECRET_MANAGER_TEST_DATABASE_URL"

var schemas atomic.Int64

func testDatabase(t *testing.T) string {
	t.Helper()
	base := os.Getenv(envTestDatabase)
	if base == "" {
		t.Skip(envTestDatabase + " is not set")
	}
	return base
}

// newBackend returns a Backend on a new, empty schema in the database at base,
// dropped when t ends.
func newBackend(t *testing.T, base string) *Backend {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("sm_test_%d_%d", os.Getpid(), schemas.Add(1))
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Error(err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, `DROP SCHEMA `+name+` CASCADE`); err != nil {
			t.Error(err)
		}
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", name)
	u.RawQuery = q.Encode()
	b, err := New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestConformance(t *testing.T) {
	base := testDatabase(t)
	storagetest.Run(t, func() storage.Backend { return newBackend(t, base) })
}

func TestConcurrentVersionsGetDistinctNumbers(t *testing.T) {
	b := newBackend(t, testDatabase(t))
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "1"}, 100); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	versions, err := b.Versions(ctx, "/app")
	if err != nil {
		t.Fatal(err)
	}
	var numbers []int
	for _, v := range versions {
		numbers = append(numbers, v.Number)
	}
	if want := []int{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}; !slices.Equal(numbers, want) {
		t.Fatalf("version numbers %v, want %v", numbers, want)
	}
}

func TestReopenKeepsData(t *testing.T) {
	b := newBackend(t, testDatabase(t))
	ctx := context.Background()
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := b.createTables(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get(ctx, "/app"); err != nil || got["A"] != "1" {
		t.Fatalf("Get after creating tables again = %v, %v", got, err)
	}
}
