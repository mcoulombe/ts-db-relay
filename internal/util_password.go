package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateSecurePassword generates a cryptographically secure 64-character hex password.
// It uses 32 random bytes which are hex-encoded.
// Hex encoding (0-9, a-f) ensures the password is safe for all database engines:
// - No special characters that need escaping
// - No quotes, semicolons, or injection risks
func GenerateSecurePassword() (string, error) {
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return hex.EncodeToString(passwordBytes), nil
}
