# Postgres only, plain SQL, no multi-database abstraction

The only supported datastore is PostgreSQL, accessed via pgx with hand-written SQL — no ORM and no database abstraction layer. Ory pays a large complexity tax for supporting four databases; we are one team building for our own deployments, so portability is pure cost. Dev environments run Postgres in Docker rather than SQLite, so every query and migration is tested against the engine that runs in production.
