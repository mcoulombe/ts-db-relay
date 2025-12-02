package internal

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRelayError_ExcludesUnderlying(t *testing.T) {
	underlying := fmt.Errorf("database connection failed for user admin@company.com on host=my-database.ai")
	relayErr := NewError(OriginExternal, "database-connection", "database connection failed", underlying)

	if strings.Contains(relayErr.Error(), "admin@company.com") {
		t.Errorf("Error() should not expose PII email, got: %s", relayErr.Error())
	}
	if strings.Contains(relayErr.Error(), "my-database.ai") {
		t.Errorf("Error() should not expose private infrastructure information, got: %s", relayErr.Error())
	}
	if relayErr.Error() != "database connection failed" {
		t.Errorf("Error() should return only the public-facing message, got: %s", relayErr.Error())
	}
}

func TestRelayError_JSONExcludesUnderlying(t *testing.T) {
	sensitiveErr := fmt.Errorf("please do not leak my key: ts-key-1234-5678")
	relayErr := NewError(OriginServer, "api-error", "API request failed", sensitiveErr)

	jsonBytes, err := json.Marshal(relayErr)
	if err != nil {
		t.Fatalf("Failed to marshal RelayError: %v", err)
	}

	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, "ts-key-1234-5678") {
		t.Errorf("marshaling relay error exposed sensitive information from the underlying error, got: %s", jsonStr)
	}
}
