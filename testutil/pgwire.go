package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lib/pq"
	"tailscale.com/tsnet"
)

// MustOpenPGWireCompatibleDB opens a database connection and performs a ping test.
func MustOpenPGWireCompatibleDB(t *testing.T, clientTsnet *tsnet.Server, connectorIP netip.Addr, pgPort int, pgDB string, pgRole string) *sql.DB {
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

	if err := pingPGWireCompatibleDB(t, db); err != nil {
		t.Fatal(err)
	}
	t.Logf("Successfully pinged database via connector at %s:%d", connectorIP, pgPort)

	return db
}

func pingPGWireCompatibleDB(t *testing.T, db *sql.DB) error {
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
