package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"tailscale.com/tsnet"
)

func StartPostgres(t *testing.T, ctx context.Context, certDir, db, adminUser, adminPassword, role string) (string, int, func(*testing.T, context.Context)) {
	t.Helper()

	pgContainer, err := postgres.Run(ctx, "postgres:13",
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_ROLE":           role,
			"POSTGRES_ADMIN_USER":     adminUser,
			"POSTGRES_ADMIN_PASSWORD": adminPassword,
		}),
		postgres.WithUsername("postgres"),
		postgres.WithDatabase(db),
		postgres.WithOrderedInitScripts("testutil/postgres/pg-create-admin.sh", "testutil/postgres/pg-create-role.sh"),
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
						HostFilePath:      "testutil/postgres/pg_hba.conf",
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
	cleanup := func(t *testing.T, ctx context.Context) {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}
	return host, port.Int(), cleanup
}

// SetupPostgresCerts creates TLS certificates for Postgres in a temp directory.
func SetupPostgresCerts(t *testing.T, dnsNames ...string) (string, string) {
	t.Helper()

	certDir := filepath.Join(t.TempDir(), "postgres-certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("failed to create cert directory: %v", err)
	}

	keyFile := filepath.Join(certDir, "server.key")
	crtFile := filepath.Join(certDir, "server.crt")
	caFile := filepath.Join(certDir, "ca.crt")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(crtFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}

	// Copy certificate as CA file
	if err := os.WriteFile(caFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	return certDir, caFile
}

// MustOpenPostgresDB opens a database connection and performs a ping test.
func MustOpenPostgresDB(t *testing.T, clientTsnet *tsnet.Server, connectorIP netip.Addr, pgPort int, pgDB string, pgRole string) *sql.DB {
	t.Helper()

	// Note: using sslmode=require (not verify-ca) because the WireGuard tunnel already provides authentication
	// and to avoid the additional test setup.
	pgConn, err := pq.NewConnector(fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=require",
		connectorIP.String(), pgPort, pgRole, pgDB))
	if err != nil {
		t.Fatalf("failed to create connector: %v", err)
	}
	// Set a custom dialer that routes through the client's tsnet.
	pgConn.Dialer(&TsnetPqDialer{
		tsnetServer: clientTsnet,
	})
	db := sql.OpenDB(pgConn)
	t.Logf("Database connection successful: client able to open database connection via the relay")

	if err := pingPostgresDB(t, db); err != nil {
		t.Fatal(err)
	}
	t.Logf("Successfully pinged database via connector at %s:%d", connectorIP, pgPort)

	return db
}

func pingPostgresDB(t *testing.T, db *sql.DB) error {
	t.Helper()

	connCtx, connCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connCancel()
	if err := db.PingContext(connCtx); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// TsnetPqDialer is a custom dialer type that implements pq.Dialer for connections via Tailscale.
type TsnetPqDialer struct {
	tsnetServer *tsnet.Server
}

func (d *TsnetPqDialer) Dial(network, address string) (net.Conn, error) {
	return d.tsnetServer.Dial(context.Background(), network, address)
}

func (d *TsnetPqDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return d.tsnetServer.Dial(ctx, network, address)
}
