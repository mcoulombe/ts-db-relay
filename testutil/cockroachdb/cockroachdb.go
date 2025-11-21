package cockroachdb

import (
	"context"
	"fmt"
	"github.com/docker/go-connections/nat"
	"github.com/tailscale/ts-db-connector/testutil"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/cockroachdb"
	"github.com/testcontainers/testcontainers-go/wait"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func StartCockroachDB(t *testing.T, ctx context.Context, certDir, db, adminUser, adminPassword, role string) (string, int, func()) {
	t.Helper()

	crdbContainer, err := cockroachdb.Run(ctx, "cockroachdb/cockroach:latest",
		testcontainers.WithEnv(map[string]string{
			"COCKROACH_ROLE":           role,
			"COCKROACH_ADMIN_USER":     adminUser,
			"COCKROACH_ADMIN_PASSWORD": adminPassword,
			"COCKROACH_DATABASE":       db,
		}),
		cockroachdb.WithDatabase(db),
		cockroachdb.WithUser("root"),
		cockroachdb.WithInitScripts("../testutil/cockroachdb/db-init.sh"),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericBindMountSource{
				HostPath: certDir,
			},
			Target: "/cockroach/cockroach-certs",
		}),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Cmd: []string{
					"--certs-dir=/cockroach/cockroach-certs",
				},
			},
		}),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("CockroachDB node starting").
					WithStartupTimeout(30*time.Second),
				wait.ForSQL("26257", "postgres", func(host string, port nat.Port) string {
					return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=require&sslrootcert=%s",
						adminUser, adminPassword, host, port.Port(), db, filepath.Join(certDir, "ca.crt"))
				}).WithStartupTimeout(30*time.Second),
			),
		),
	)
	if err != nil {
		if crdbContainer != nil {
			logs, _ := crdbContainer.Logs(ctx)
			logBytes, _ := io.ReadAll(logs)
			t.Logf("Container logs:\n%s", string(logBytes))
			if err := crdbContainer.Terminate(ctx); err != nil {
				t.Logf("failed to terminate cockroachdb container: %v", err)
			}
		}
		t.Fatalf("failed to start cockroachdb container: %v", err)
	}

	host, err := crdbContainer.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}
	port, err := crdbContainer.MappedPort(ctx, "26257")
	if err != nil {
		t.Fatalf("failed to get mapped port: %v", err)
	}
	cleanup := func() {
		if err := crdbContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate cockroachdb container: %v", err)
		}
	}
	return host, port.Int(), cleanup
}

// SetupDBCerts creates TLS certificates for CockroachDB in a temp directory.
// CockroachDB requires a CA cert, a cert for each DB node, and a client cert for any users using certificate auth.
// We only create a client certificate for the root user that used to initialise the database.
func SetupDBCerts(t *testing.T) (string, string) {
	t.Helper()

	certDir := filepath.Join(t.TempDir(), "cockroachdb-certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("failed to create cert directory: %v", err)
	}

	caKey, caCert, caFile := testutil.CreateCACertificate(t, certDir, "ca", "Cockroach CA", "CockroachDB")
	testutil.CreateServerCertificate(t, certDir, "node", caKey, caCert, "node", "localhost", "cockroach-db")
	testutil.CreateClientCertificate(t, certDir, caKey, caCert, "root")

	return certDir, caFile
}
