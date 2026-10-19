VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/AimTune/tenarium/pkg/server.Version=$(VERSION)
TEST_PG ?= postgres://postgres:postgres@localhost:55432/tenarium?sslmode=disable

.PHONY: build build-tools test test-integration test-ui lint run docker up down test-db docs docs-serve

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/tenarium ./cmd/tenarium

build-tools:
	go build -o bin/tenarium-build ./cmd/tenarium-build

test:
	go test -short ./...

# Full suite incl. PostgreSQL; start a database with `make test-db`.
test-integration:
	TENARIUM_TEST_POSTGRES_DSN="$(TEST_PG)" go test -count=1 ./...

# Admin UI browser tests (Playwright); builds and starts a throwaway server.
test-ui:
	cd tests/ui && npm ci && npx playwright install chromium && npx playwright test

test-db:
	docker run -d --name tenarium-test-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=tenarium -p 55432:5432 postgres:17-alpine

lint:
	golangci-lint run ./...

run:
	TENARIUM_API_KEY=dev go run ./cmd/tenarium -config config.example.yaml

docker:
	docker build --build-arg VERSION=$(VERSION) -t tenarium:$(VERSION) .

up:
	docker compose up -d --build

down:
	docker compose down

# Documentation website (Docusaurus, Node 22); see website/.
docs:
	cd website && npm ci && npm run build

docs-serve:
	cd website && npm ci && npm start
