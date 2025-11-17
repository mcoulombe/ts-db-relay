.PHONY: test_acc

test_acc:
	go test -args acc -v ./...
