-- Fixed-window rate-limit counters. Platform-level (no RLS): keys embed
-- tenant scope where it matters, and counting must work before a tenant
-- transaction exists — and must survive one rolling back, so attempts
-- always burn budget.
CREATE TABLE rate_limits (
    key          text NOT NULL,
    window_start timestamptz NOT NULL,
    count        int NOT NULL DEFAULT 1,
    PRIMARY KEY (key, window_start)
);
