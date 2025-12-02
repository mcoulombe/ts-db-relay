package internal

import (
	"fmt"
	"time"
)

// GenerateEphemeralUsername generates a username suitable for ephemeral database users.
// The pattern is "ts-<original>-<timestamp>" where <original> is the principal being impersonated
// and <timestamp> is the current Unix timestamp in milliseconds.
// If the generated username exceeds maxLength, the <original> part is truncated to fit within the limit.
func GenerateEphemeralUsername(original string, maxLength int) (string, error) {
	if original == "" {
		return "", fmt.Errorf("original username cannot be empty")
	}

	timestamp := time.Now().UnixMilli()
	generatedUsername := fmt.Sprintf("ts-%s-%d", original, timestamp)
	
	if len(generatedUsername) > maxLength {
		invariantCharacters := fmt.Sprintf("ts--%d", timestamp)
		if len(invariantCharacters) >= maxLength {
			return "", fmt.Errorf("maxLength %d is too small to generate a valid username, must be at least %d", maxLength, len(invariantCharacters)+1)
		}

		truncated := original[:maxLength-len(invariantCharacters)]
		generatedUsername = fmt.Sprintf("ts-%s-%d", truncated, timestamp)
	}

	return generatedUsername, nil
}
