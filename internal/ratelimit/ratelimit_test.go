package ratelimit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration test; runs only against a migrated database:
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
