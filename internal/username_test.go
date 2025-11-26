package internal

import (
	"strings"
	"testing"
)

func TestGenerateEphemeralUsername(t *testing.T) {
	tests := []struct {
		name       string
		original   string
		maxLength  int
		wantPrefix string
		wantErr    string
	}{
		{
			name:       "normal username",
			original:   "foo",
			maxLength:  128,
			wantPrefix: "ts-foo-",
		},
		{
			name:       "username too long gets truncated at the end",
			original:   "a" + strings.Repeat("b", 100) + "c",
			maxLength:  20,
			wantPrefix: "ts-abb-",
		},
		{
			name:      "empty original principal returns error",
			original:  "",
			maxLength: 128,
			wantErr:   "original username cannot be empty",
		},
		{
			name:      "maxLength too small returns error",
			original:  "alice",
			maxLength: 10,
			wantErr:   "maxLength 10 is too small to generate a valid username, must be at least 18",
		},
		{
			name:      "negative maxLength too small returns error",
			original:  "alice",
			maxLength: -1,
			wantErr:   "maxLength -1 is too small to generate a valid username, must be at least 18",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateEphemeralUsername(tt.original, tt.maxLength)

			if tt.wantErr == "" && err != nil {
				t.Errorf("GenerateEphemeralUsername() unexpected error = %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("GenerateEphemeralUsername() error = nil, want %q", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr {
					t.Errorf("GenerateEphemeralUsername() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}

			if len(got) > tt.maxLength {
				t.Errorf("GenerateEphemeralUsername() length = %d, want <= %d", len(got), tt.maxLength)
			}

			if tt.wantPrefix != "" && !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("GenerateEphemeralUsername() = %q, want prefix %q", got, tt.wantPrefix)
			}

			parts := strings.Split(got, "-")
			if tt.wantPrefix != "" && len(parts) != 3 {
				t.Errorf("GenerateEphemeralUsername() number of parts = %d, want 3 parts", len(parts))
			}
		})
	}
}
