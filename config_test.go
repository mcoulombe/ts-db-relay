package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Run("file exists", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "config-*.json")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := []byte(`{"tailscale": {}}`)
		_, err = tmpFile.Write(content)
		require.NoError(t, err)
		tmpFile.Close()

		rawCfg, err := LoadConfig(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, content, rawCfg)
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/path/to/config.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})
}

func TestParseConfig_InvalidJSON(t *testing.T) {
	tests := []struct {
		name   string
		config string
		errMsg string
	}{
		{
			name:   "invalid HuJSON syntax",
			config: `{tailscale: }`,
			errMsg: "failed to parse config file",
		},
		{
			name:   "invalid JSON structure",
			config: `{"tailscale": "not an object"}`,
			errMsg: "failed to unmarshal config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.config))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	tmpDir, cleanup := setupTestDir(t)
	defer cleanup()

	caFile := createFakeCAFile(t, tmpDir)

	minimalConfig := fmt.Sprintf(`{
		"tailscale": {},
		"connector": {},
		"databases": {
			"testdb": {
				"engine": "postgres",
				"ca_file": "%s",
				"admin_user": "admin",
				"admin_password": "pass"
			}
		}
	}`, caFile)

	config, err := ParseConfig([]byte(minimalConfig))
	require.NoError(t, err)

	assert.Equal(t, "https://login.tailscale.com", config.Tailscale.ControlURL)
	assert.Equal(t, "./data/ts-db-connector", config.Tailscale.StateDir)
	assert.Equal(t, "ts-db-connector", config.Tailscale.Hostname)
	assert.Equal(t, 8080, config.Connector.AdminPort)

	db := config.Databases["testdb"]
	assert.Equal(t, "localhost", db.Host)
	assert.Equal(t, 5432, db.Port)
	assert.Equal(t, 5432, db.ListeningPort)
}

func TestParseConfig_ValidationErrors(t *testing.T) {
	tmpDir, cleanup := setupTestDir(t)
	defer cleanup()

	validCAFile := createFakeCAFile(t, tmpDir)
	nonExistentCA := filepath.Join(tmpDir, "nonexistent.crt")

	tests := []struct {
		name   string
		config string
		errMsg string
	}{
		{
			name: "invalid control_url scheme",
			config: `{
				"tailscale": {
					"control_url": "ftp://example.com"
				}
			}`,
			errMsg: "scheme must be http or https",
		},
		{
			name: "control_url with trailing slash",
			config: `{
				"tailscale": {
					"control_url": "https://example.com/"
				}
			}`,
			errMsg: "must not have a trailing slash",
		},
		{
			name: "invalid hostname too long",
			config: `{
				"tailscale": {
					"hostname": "verylonghostnamethatiswaytoomanycharsandexceedsthesixtythreecharlimit"
				}
			}`,
			errMsg: "must be between 1 and 63 characters long",
		},
		{
			name: "invalid hostname starts with number",
			config: `{
				"tailscale": {
					"hostname": "1invalid"
				}
			}`,
			errMsg: "must start and end with a letter",
		},
		{
			name: "invalid hostname special chars",
			config: `{
				"tailscale": {
					"hostname": "invalid_hostname"
				}
			}`,
			errMsg: "must start and end with a letter",
		},
		{
			name: "missing database engine",
			config: `{
				"databases": {
					"testdb": {
						"host": "localhost",
						"port": 5432,
						"ca_file": "/tmp/ca.crt",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`,
			errMsg: `database "testdb": engine is required`,
		},
		{
			name: "invalid database engine",
			config: `{
				"databases": {
					"testdb": {
						"engine": "not-supported",
						"host": "localhost",
						"port": 3306,
						"ca_file": "/tmp/ca.crt",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`,
			errMsg: `unsupported engine "not-supported"`,
		},
		{
			name: "port out of range high",
			config: `{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 99999,
						"ca_file": "/tmp/ca.crt",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`,
			errMsg: "must be between 0 and 65535",
		},
		{
			name: "port out of range negative",
			config: `{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": -1,
						"ca_file": "/tmp/ca.crt",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`,
			errMsg: "must be between 0 and 65535",
		},
		{
			name: "missing ca_file",
			config: `{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 5432,
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`,
			errMsg: `database "testdb": ca_file is required`,
		},
		{
			name: "ca_file does not exist",
			config: fmt.Sprintf(`{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 5432,
						"ca_file": "%s",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`, nonExistentCA),
			errMsg: "file does not exist",
		},
		{
			name: "ca_file is a directory",
			config: fmt.Sprintf(`{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 5432,
						"ca_file": "%s",
						"admin_user": "admin",
						"admin_password": "pass"
					}
				}
			}`, tmpDir),
			errMsg: "path is a directory",
		},
		{
			name: "missing admin_user",
			config: fmt.Sprintf(`{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 5432,
						"ca_file": "%s",
						"admin_password": "pass"
					}
				}
			}`, validCAFile),
			errMsg: `database "testdb": admin_user is required`,
		},
		{
			name: "missing admin_password",
			config: fmt.Sprintf(`{
				"databases": {
					"testdb": {
						"engine": "postgres",
						"host": "localhost",
						"port": 5432,
						"ca_file": "%s",
						"admin_user": "admin"
					}
				}
			}`, validCAFile),
			errMsg: `database "testdb": admin_password is required`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.config))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestParseConfig_EnvVariableResolution(t *testing.T) {
	t.Run("well-known env vars", func(t *testing.T) {
		tmpDir, cleanup := setupTestDir(t)
		defer cleanup()

		customStateDir := filepath.Join(tmpDir, "custom-state")

		os.Setenv("TS_SERVER", "https://custom.tailscale.com")
		os.Setenv("TS_STATE_DIR", customStateDir)
		os.Setenv("TS_HOSTNAME", "custom-hostname")
		os.Setenv("TS_AUTHKEY", "tskey-custom-auth")
		os.Setenv("TS_CLIENT_ID", "custom-client-id")
		os.Setenv("TS_CLIENT_SECRET", "custom-client-secret")
		os.Setenv("ID_TOKEN", "custom-id-token")
		defer func() {
			os.Unsetenv("TS_SERVER")
			os.Unsetenv("TS_STATE_DIR")
			os.Unsetenv("TS_HOSTNAME")
			os.Unsetenv("TS_AUTHKEY")
			os.Unsetenv("TS_CLIENT_ID")
			os.Unsetenv("TS_CLIENT_SECRET")
			os.Unsetenv("ID_TOKEN")
		}()

		config := `{
			"tailscale": {},
			"connector": {},
			"databases": {}
		}`

		cfg, err := ParseConfig([]byte(config))
		require.NoError(t, err)
		assert.Equal(t, "https://custom.tailscale.com", cfg.Tailscale.ControlURL)
		assert.Equal(t, customStateDir, cfg.Tailscale.StateDir)
		assert.Equal(t, "custom-hostname", cfg.Tailscale.Hostname)
		assert.Equal(t, "tskey-custom-auth", cfg.Tailscale.AuthKey)
		assert.Equal(t, "custom-client-id", cfg.Tailscale.ClientID)
		assert.Equal(t, "custom-client-secret", cfg.Tailscale.ClientSecret)
		assert.Equal(t, "custom-id-token", cfg.Tailscale.IDToken)
	})

	t.Run("env: prefix", func(t *testing.T) {
		os.Setenv("MY_CUSTOM_HOST", "192.168.1.1")
		defer os.Unsetenv("MY_CUSTOM_HOST")

		tmpDir, cleanup := setupTestDir(t)
		defer cleanup()

		caFile := createFakeCAFile(t, tmpDir)

		config := fmt.Sprintf(`{
			"databases": {
				"testdb": {
					"engine": "postgres",
					"host": "env:MY_CUSTOM_HOST",
					"ca_file": "%s",
					"admin_user": "admin",
					"admin_password": "pass"
				}
			}
		}`, caFile)

		cfg, err := ParseConfig([]byte(config))
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", cfg.Databases["testdb"].Host)
	})

	t.Run("env: prefix missing variable", func(t *testing.T) {
		config := `{
			"tailscale": {
				"control_url": "env:NONEXISTENT_VAR",
			}
		}`

		_, err := ParseConfig([]byte(config))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to look up environment variable")
	})
}

func TestParseConfig_FileResolution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	t.Run("file: prefix", func(t *testing.T) {
		secretFile := filepath.Join(tmpDir, "secret.txt")
		err := os.WriteFile(secretFile, []byte("my-secret-password\n"), 0644)
		require.NoError(t, err)

		caFile := filepath.Join(tmpDir, "ca.crt")
		err = os.WriteFile(caFile, []byte("fake cert"), 0644)
		require.NoError(t, err)

		config := fmt.Sprintf(`{
			"databases": {
				"testdb": {
					"engine": "postgres",
					"ca_file": "%s",
					"admin_user": "admin",
					"admin_password": "file:%s"
				}
			}
		}`, caFile, secretFile)

		cfg, err := ParseConfig([]byte(config))
		require.NoError(t, err)
		assert.Equal(t, "my-secret-password", cfg.Databases["testdb"].AdminPassword)
	})

	t.Run("file: prefix missing file", func(t *testing.T) {
		caFile := filepath.Join(tmpDir, "ca.crt")
		err := os.WriteFile(caFile, []byte("fake cert"), 0644)
		require.NoError(t, err)

		config := fmt.Sprintf(`{
			"databases": {
				"testdb": {
					"engine": "postgres",
					"ca_file": "%s",
					"admin_user": "admin",
					"admin_password": "file:/nonexistent/secret.txt"
				}
			}
		}`, caFile)

		_, err = ParseConfig([]byte(config))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to read file")
	})
}

func TestParseConfig_ValidComplete(t *testing.T) {
	tmpDir, cleanup := setupTestDir(t)
	defer cleanup()

	caFile := createFakeCAFile(t, tmpDir)

	config := fmt.Sprintf(`{
        /*
         * Some HuJSON comment
         */
		"tailscale": { // Another comment
			"control_url": "https://custom.tailscale.com",
			"state_dir": "%s/state",
			"hostname": "my-connector",
			"authkey": "tskey-auth-test"
		},
		"connector": {
			"admin_port": 9090
		},
		"databases": {
			"pgdb": {
				"engine": "postgres",
				"host": "pg.example.com",
				"port": 5433,
				"listening_port": 5432,
				"ca_file": "%s",
				"admin_user": "pgadmin",
				"admin_password": "pgpass"
			},
			"cockroachdb": {
				"engine": "cockroachdb",
				"host": "crdb.example.com",
				"port": 26258,
				"ca_file": "%s",
				"admin_user": "crdbadmin",
				"admin_password": "crdbpass"
			},
			"mongodb": {
				"engine": "mongodb",
				"host": "mongo.example.com",
				"port": 27018,
				"ca_file": "%s",
				"admin_user": "mongoadmin",
				"admin_password": "mongopass"
			}
		}
	}`, tmpDir, caFile, caFile, caFile)

	cfg, err := ParseConfig([]byte(config))
	require.NoError(t, err)

	assert.Equal(t, "https://custom.tailscale.com", cfg.Tailscale.ControlURL)
	assert.Equal(t, filepath.Join(tmpDir, "state"), cfg.Tailscale.StateDir)
	assert.Equal(t, "my-connector", cfg.Tailscale.Hostname)
	assert.Equal(t, "tskey-auth-test", cfg.Tailscale.AuthKey)
	assert.Equal(t, 9090, cfg.Connector.AdminPort)

	assert.Len(t, cfg.Databases, 3)

	pgdb := cfg.Databases["pgdb"]
	assert.Equal(t, "postgres", string(pgdb.Engine))
	assert.Equal(t, "pg.example.com", pgdb.Host)
	assert.Equal(t, 5433, pgdb.Port)
	assert.Equal(t, 5432, pgdb.ListeningPort)

	crdb := cfg.Databases["cockroachdb"]
	assert.Equal(t, "cockroachdb", string(crdb.Engine))
	assert.Equal(t, 26258, crdb.ListeningPort)

	mdb := cfg.Databases["mongodb"]
	assert.Equal(t, "mongodb", string(mdb.Engine))
	assert.Equal(t, 27018, mdb.Port)
}

func setupTestDir(t *testing.T) (string, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "config-test-")
	require.NoError(t, err)
	cleanup := func() { os.RemoveAll(tmpDir) }
	return tmpDir, cleanup
}

func createFakeCAFile(t *testing.T, dir string) string {
	t.Helper()

	caFile := filepath.Join(dir, "ca.crt")
	err := os.WriteFile(caFile, []byte("fake cert"), 0644)
	require.NoError(t, err)
	return caFile
}
