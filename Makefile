default: dev

.PHONY: dev
dev:
	go build -gcflags="all=-N -l" -o ./cmd/ts-db-connector .

.PHONY: test
test:
	go test -v ./...

.PHONY: test_acc
test_acc:
	go test -args acc -v ./...
