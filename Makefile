.PHONY: build test test-integration vet fmt run migrate db-up db-down

# The database the integration tests run against: the compose one, which
# publishes on 35432 to stay clear of any Postgres already on 5432.
# Override to point somewhere else:
#   make test-integration PRATU_TEST_DATABASE_URL=...
PRATU_TEST_DATABASE_URL ?= postgres://pratu:pratu@localhost:35432/pratu?sslmode=disable

build:
	go build -o bin/pratu ./cmd/pratu

# Unit tests only: the database-backed tests skip themselves.
test:
	go test ./...

# Everything, including the tests that drive the real handlers against a
# real Postgres. The suite migrates the database itself.
test-integration: db-up
	PRATU_TEST_DATABASE_URL="$(PRATU_TEST_DATABASE_URL)" go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

run: build
	./bin/pratu serve -config pratu.yaml

migrate: build
	./bin/pratu migrate -config pratu.yaml

db-up:
	docker compose up -d --wait postgres

db-down:
	docker compose down
