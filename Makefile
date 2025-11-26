default: dev

.PHONY: dev
dev:
	go build -gcflags="all=-N -l" -o ./bin/ts-db-connector ./cmd/ts-db-connector

.PHONY: build
build:
	go build -o ./bin/ts-db-connector ./cmd/ts-db-connector

SERVICES ?= postgres cockroachdb mongodb # Default to all supported engines
.PHONY: containers
containers:
	docker compose -f test-setup/compose.yml down && \
	docker compose -f test-setup/compose.yml up --build setup $(SERVICES)

CONFIG ?= data/.config.hujson # Default config file path
.PHONY: run
run: dev
	@if [ -z "$$TS_AUTHKEY" ]; then \
		echo "Warning: TS_AUTHKEY environment variable is not set"; \
		echo "If ts-db-connector is not already part of a tailnet, it will fail to connect"; \
		echo "Set it with: export TS_AUTHKEY=tskey-auth-1234"; \
		echo ""; \
	fi
	@if command -v grcat >/dev/null 2>&1; then \
		./bin/ts-db-connector --config=$(CONFIG) 2>&1 | grcat .grc/slog.grc; \
	else \
		./bin/ts-db-connector --config=$(CONFIG); \
	fi

.PHONY: test
test:
	go test -v ./internal

.PHONY: testacc
testacc:
	go test -v ./internal -args -acc

.PHONY: testacc_local
testacc_local:
	TEST_CONTROL_URL="http://localhost:31544" TEST_APIKEY=$$(jq -r .apiKey /tmp/terraform-api-key.json) go test -v ./internal -acc

