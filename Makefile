.PHONY: build test vet fmt run migrate db-up db-down

build:
	go build -o bin/pratu ./cmd/pratu

test:
	go test ./...

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
