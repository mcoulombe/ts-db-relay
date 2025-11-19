package postgres

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/tailscale/ts-db-connector/testutil"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func StartPostgres(t *testing.T, ctx context.Context, certDir, db, adminUser, adminPassword, role string) (string, int, func()) {
	t.Helper()

	pgContainer, err := postgres.Run(ctx, "postgres:13",
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_ROLE":           role,
			"POSTGRES_ADMIN_USER":     adminUser,
			"POSTGRES_ADMIN_PASSWORD": adminPassword,
		}),
		postgres.WithUsername("postgres"),
		postgres.WithDatabase(db),
		postgres.WithOrderedInitScripts("../testutil/postgres/db-init.sh"),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericBindMountSource{
				HostPath: certDir,
			},
			Target: "/var/lib/postgresql/certs",
		}),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Cmd: []string{
					"-c", "ssl=on",
					"-c", "ssl_cert_file=/var/lib/postgresql/certs/server.crt",
					"-c", "ssl_key_file=/var/lib/postgresql/certs/server.key",
					"-c", "ssl_ca_file=/var/lib/postgresql/certs/ca.crt",
					"-c", "listen_addresses=*",
				},
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      "../testutil/postgres/pg_hba.conf",
						ContainerFilePath: "/var/lib/postgresql/pg_hba.conf",
						FileMode:          0600,
					},
				},
			},
		}),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(30*time.Second),
				wait.ForSQL("5432", "postgres", func(host string, port nat.Port) string {
					return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=verify-ca sslrootcert=%s",
						host, port.Port(), adminUser, adminPassword, db, filepath.Join(certDir, "ca.crt"))
				}).WithStartupTimeout(30*time.Second),
			),
		),
	)
	if err != nil {
		if pgContainer != nil {
			logs, _ := pgContainer.Logs(ctx)
			logBytes, _ := io.ReadAll(logs)
			t.Logf("Container logs:\n%s", string(logBytes))
			if err := pgContainer.Terminate(ctx); err != nil {
				t.Logf("failed to terminate postgres container: %v", err)
			}
		}
		t.Fatalf("failed to start postgres container: %v", err)
	}

	host, err := pgContainer.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}
	port, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get mapped port: %v", err)
	}
	cleanup := func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}
	return host, port.Int(), cleanup
}

// SetupDBCerts creates TLS certificates for Postgres in a temp directory.
func SetupDBCerts(t *testing.T) (string, string) {
	t.Helper()

	certDir := filepath.Join(t.TempDir(), "postgres-certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("failed to create cert directory: %v", err)
	}

	caKey, caCert, caFile := testutil.CreateCACertificate(t, certDir, "ca", "Postgres CA")
	testutil.CreateServerCertificate(t, certDir, "server", caKey, caCert, "localhost", "postgres-db")

	return certDir, caFile
}
