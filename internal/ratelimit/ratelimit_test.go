package ratelimit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/storage"
)

// TestMain migrates the test database, so a fresh one works with no setup
// beyond an unprivileged role. Migrate serializes on an advisory lock, so
// the other packages' suites may do the same concurrently.
func TestMain(m *testing.M) {
	if url := os.Getenv("PRATU_TEST_DATABASE_URL"); url != "" {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "integration tests: connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := storage.Migrate(ctx, pool); err != nil {
			fmt.Fprintf(os.Stderr, "integration tests: migrate: %v\n", err)
			os.Exit(1)
		}
		pool.Close()
	}
	os.Exit(m.Run())
}

// Integration test; runs only against a database (TestMain migrates it):
//
//	PRATU_TEST_DATABASE_URL=postgres://pratu:pratu@localhost:5432/pratu?sslmode=disable go test ./internal/ratelimit/
func TestAllow(t *testing.T) {
	url := os.Getenv("PRATU_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PRATU_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	l := New(pool)
	key := fmt.Sprintf("test:%d", time.Now().UnixNano())

	for i := 1; i <= 3; i++ {
		ok, _, err := l.Allow(ctx, key, 3, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	ok, retryAfter, err := l.Allow(ctx, key, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("hit 4 should be blocked")
	}
	if retryAfter <= 0 || retryAfter > time.Hour {
		t.Errorf("retryAfter = %v, want within (0, 1h]", retryAfter)
	}

	if _, err := l.Cleanup(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := l.Allow(ctx, key, 3, time.Hour); !ok {
		t.Error("cleanup should have reset the counter")
	}
}
