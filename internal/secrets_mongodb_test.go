package internal

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestMongoDBPlugin_Initialize(t *testing.T) {
	plugin := &mongoDBPlugin{}
	ctx := context.Background()

	tests := []struct {
		name        string
		config      map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing client_options",
			config:      map[string]interface{}{},
			wantErr:     true,
			errContains: "invalid config",
		},
		{
			name: "nil client_options",
			config: map[string]interface{}{
				"client_options": (*options.ClientOptions)(nil),
			},
			wantErr:     true,
			errContains: "invalid config",
		},
		{
			name: "empty URI in client_options",
			config: map[string]interface{}{
				"client_options": options.Client(),
			},
			wantErr:     true,
			errContains: "invalid config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := plugin.Initialize(ctx, dbplugin.InitializeRequest{
				Config:           tt.config,
				VerifyConnection: false,
			})

			if tt.wantErr && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestMongoDBPlugin_NewUser(t *testing.T) {
	plugin := &mongoDBPlugin{}
	ctx := context.Background()

	tests := []struct {
		name        string
		req         dbplugin.NewUserRequest
		errContains string
	}{
		{
			name: "missing username",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`{"db": "testdb"}`},
				},
			},
			errContains: "username is required",
		},
		{
			name: "missing role name",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`{"db": "testdb"}`},
				},
			},
			errContains: "role name (target user to impersonate) is required",
		},
		{
			name: "missing password",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "",
				Statements: dbplugin.Statements{
					Commands: []string{`{"db": "testdb"}`},
				},
			},
			errContains: "password is required",
		},
		{
			name: "no statements",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{},
				},
			},
			errContains: "exactly one creation statement is required",
		},
		{
			name: "multiple statements",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`{"db": "testdb"}`, `{"db": "testdb2"}`},
				},
			},
			errContains: "exactly one creation statement is required",
		},
		{
			name: "invalid JSON in statement",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`invalid json`},
				},
			},
			errContains: "failed to parse creation statement",
		},
		{
			name: "missing authSource field in statement",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`{}`},
				},
			},
			errContains: "auth database where the target user is defined must be specified",
		},
		{
			name: "empty authSource field in statement",
			req: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "newuser",
					RoleName:    "targetuser",
				},
				Password: "password123",
				Statements: dbplugin.Statements{
					Commands: []string{`{"authSource": ""}`},
				},
			},
			errContains: "auth database where the target user is defined must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := plugin.NewUser(ctx, tt.req)

			if tt.errContains == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q but got none", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestEncodeMongoDBUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		authDB   string
		expected string
	}{
		{
			name:     "simple username",
			username: "testuser",
			authDB:   "admin",
			expected: "testuser@admin",
		},
		{
			name:     "username with @ symbol",
			username: "user@example.com",
			authDB:   "testdb",
			expected: "user%40example.com@testdb",
		},
		{
			name:     "username with multiple @ symbols",
			username: "user@test@example.com",
			authDB:   "mydb",
			expected: "user%40test%40example.com@mydb",
		},
		{
			name:     "username with special characters",
			username: "user+test@example.com",
			authDB:   "mydb",
			expected: "user%2Btest%40example.com@mydb",
		},
		{
			name:     "username with spaces",
			username: "test user",
			authDB:   "admin",
			expected: "test+user@admin",
		},
		{
			name:     "username with URL special characters",
			username: "user/name?test=true&foo=bar",
			authDB:   "testdb",
			expected: "user%2Fname%3Ftest%3Dtrue%26foo%3Dbar@testdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeMongoDBUsername(tt.username, tt.authDB)

			if encoded != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, encoded)
			}
		})
	}
}

func TestDecodeMongoDBUsername(t *testing.T) {
	tests := []struct {
		name        string
		encoded     string
		errContains string
	}{
		{
			name:        "missing @ symbol",
			encoded:     "usernamewithnoat",
			errContains: "invalid encoded username format",
		},
		{
			name:        "empty string",
			encoded:     "",
			errContains: "invalid encoded username format",
		},
		{
			name:        "only @ symbol",
			encoded:     "@",
			errContains: "invalid encoded username format",
		},
		{
			name:        "only username with @",
			encoded:     "username@",
			errContains: "invalid encoded username format",
		},
		{
			name:        "only @ with authDB",
			encoded:     "@admin",
			errContains: "invalid encoded username format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeMongoDBUsername(tt.encoded)

			if tt.errContains == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q but got none", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}
