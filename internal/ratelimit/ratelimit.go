// Package ratelimit provides fixed-window rate limiting backed by
// Postgres — deliberately no Redis dependency; auth-server traffic rates
// are well within what a single upserted counter row handles.
package ratelimit

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Limiter struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Limiter {
	return &Limiter{pool: pool}
}

// Allow burns one hit against key and reports whether the key stays
// within limit for the current window. It runs on its own connection,
// outside any caller transaction: a rolled-back request still counts.
// When blocked, retryAfter says when the window rolls over.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (ok bool, retryAfter time.Duration, err error) {
	windowStart := time.Now().Truncate(window)
	var count int
	err = l.pool.QueryRow(ctx,
		`INSERT INTO rate_limits (key, window_start) VALUES ($1, $2)
		 ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1
		 RETURNING count`,
		key, windowStart,
	).Scan(&count)
	if err != nil {
		return false, 0, err
	}
	if count > limit {
		return false, time.Until(windowStart.Add(window)), nil
	}
	return true, 0, nil
}

// Cleanup drops counter rows whose window ended more than keep ago.
func (l *Limiter) Cleanup(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := l.pool.Exec(ctx,
		`DELETE FROM rate_limits WHERE window_start < $1`, time.Now().Add(-keep))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
