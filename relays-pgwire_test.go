//go:build acc
// +build acc

package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/ts-db-connector/testutil"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func TestRelayServe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Disable ryuk to avoid the overhead of running another container on every test run.
	// It isn't required, as we're already running the container cleanup with defer on exit.
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	pgInstance := "my-postgres-1"
	pgDb := "testdb"
	pgAdminUser := "admin"
	pgAdminPassword := "admin123"
	pgRole := "testrole"

	pgCertDir, pgCAFile := testutil.SetupPostgresCerts(t, "localhost", "postgres-db")
	pgHost, pgPort, pgCleanup, err := testutil.StartPostgres(t, ctx, pgCertDir, pgDb, pgAdminUser, pgAdminPassword, pgRole)
	if err != nil {
		t.Fatal(err)
	}
	defer pgCleanup(t, ctx)

	connectorConfigJSON := fmt.Sprintf(`{
        "databases": {
            %q: {
                "engine": "postgres",
                "host": %q,
                "port": %d,
                "ca_file": %q,
                "admin_user": %q,
                "admin_password": %q
            }
        }
    }`, pgInstance, pgHost, pgPort, pgCAFile, pgAdminUser, pgAdminPassword)

	pgAppCap, err := dbConnectorAppCap(pgInstance, pgDb, pgPort, pgRole)
	if err != nil {
		t.Fatal(err)
	}

	controlURL, control := testutil.StartControl(t)

	connectorTsnet, connectorIP, connectorNodeKey := testutil.StartTsnetServer(t, ctx, controlURL, "test-db-connector")
	defer connectorTsnet.Close()
	clientTsnet, clientIP, clientNodeKey := testutil.StartTsnetServer(t, ctx, controlURL, "test-db-client")
	defer clientTsnet.Close()

	filterRules := dbConnectorFilterRules(clientIP, connectorIP, pgAppCap)
	if err := testutil.InjectMapResponse(t, control, connectorNodeKey, clientNodeKey, filterRules); err != nil {
		t.Fatal(err)
	}
	if err := testutil.InjectMapResponse(t, control, clientNodeKey, connectorNodeKey, []tailcfg.FilterRule{}); err != nil {
		t.Fatal(err)
	}

	connector, err := newConnector(connectorTsnet, []byte(connectorConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	connectorCleanup, err := connector.start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connectorCleanup()

	// Perform various sanity checks of the connectivity between DB clientTsnet and DB connectorTsnet.
	// They helped debugging during the initial test setup. WE MIGHT NOT NEED THEM ALL.

	// (1) DB clientTsnet can see the connectorTsnet (tailscale status)
	dbClientLocalClient, err := clientTsnet.LocalClient()
	status, err := dbClientLocalClient.Status(ctx)
	if err != nil {
		t.Fatalf("Failed to get client status: %v", err)
	}
	t.Logf("client status: %d peers", len(status.Peer))
	for ip, peer := range status.Peer {
		t.Logf("  Peer: %s -> %s", ip, peer.HostName)
	}

	// (2) DB clientTsnet can ping the connectorTsnet (tailscale ping)
	if _, err := dbClientLocalClient.Ping(ctx, connectorIP, tailcfg.PingTSMP); err != nil {
		t.Fatal(err)
	}
	t.Log("Ping check successful: DB client able to ping DB connector")

	// (3) DB clientTsnet can connect to the relay port that the connectorTsnet is listening on.
	t.Logf("Testing direct tsnet dial to %s:%d", connectorIP.String(), pgPort)
	testConn, err := clientTsnet.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", connectorIP.String(), pgPort))
	if err != nil {
		t.Fatalf("Failed to dial via tsnet: %v", err)
	}
	t.Logf("Direct tsnet connection successful.")
	testConn.Close()

	// (4) DB clientTsnet can connect to the database via the connectorTsnet and run various queries.
	t.Logf("Now trying pgwire connection...")
	db := testutil.OpenPostgresDB(t, connectorIP, pgPort, pgRole, pgDb, clientTsnet)
	defer db.Close()

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	t.Logf("Connecting to database via tsnet connector at %s:%d", connectorIP.String(), pgPort)
	if err := db.PingContext(connCtx); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}
	t.Logf("Successfully connected to database via tsnet connector")

	// The actual test: clientTsnet can run various queries via the connectorTsnet.
	queryCtx, queryCancel := context.WithTimeout(ctx, 5*time.Second)
	defer queryCancel()

	var version string
	err = db.QueryRowContext(queryCtx, "SELECT version()").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query database: %v", err)
	}
	t.Logf("Database version: %s", version)

	_, err = db.ExecContext(queryCtx, "CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY, name TEXT)")
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	_, err = db.ExecContext(queryCtx, "INSERT INTO test_table (name) VALUES ($1)", "test_value")
	if err != nil {
		t.Fatalf("failed to insert data: %v", err)
	}

	var name string
	err = db.QueryRowContext(queryCtx, "SELECT name FROM test_table WHERE name = $1", "test_value").Scan(&name)
	if err != nil {
		t.Fatalf("failed to query inserted data: %v", err)
	}
	if name != "test_value" {
		t.Errorf("expected name 'test_value', got '%s'", name)
	}

	t.Logf("Successfully inserted and queried data via connector")
}

func dbConnectorAppCap(pgInstance string, pgDB string, pgPort int, pgRole string) (string, error) {
	capValue, err := json.Marshal(dbCapability{
		Engine: "postgres",
		Port:   pgPort,
		Access: []accessSchema{
			{
				Databases: []string{pgDB},
				Roles:     []string{pgRole},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal capability: %v", err)
	}
	return fmt.Sprintf(`{%q: %s}`, pgInstance, capValue), nil
}

func dbConnectorFilterRules(dbClientIP netip.Addr, dbConnectorIP netip.Addr, connectorAppCap string) []tailcfg.FilterRule {
	return []tailcfg.FilterRule{
		{
			SrcIPs: []string{dbClientIP.String()},
			DstPorts: []tailcfg.NetPortRange{
				{
					IP:    fmt.Sprintf("%s/32", dbConnectorIP), // TODO: there must be a better way!?
					Ports: tailcfg.PortRange{First: 0, Last: 65535},
				},
			},
		},
		{
			SrcIPs: []string{dbClientIP.String()},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix(fmt.Sprintf("%s/32", dbConnectorIP)), // TODO: there must be a better way!?
				},
				CapMap: tailcfg.PeerCapMap{
					tsDBDatabaseCapability: []tailcfg.RawMessage{
						tailcfg.RawMessage(connectorAppCap),
					},
				},
			}},
		},
	}
}

type Connector struct {
	server *tsnet.Server
	config *Config
}

func newConnector(s *tsnet.Server, configJSON []byte) (*Connector, error) {
	config, err := LoadConfig([]byte(configJSON))
	if err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Connector{
		server: s,
		config: config,
	}, nil
}

func (c *Connector) start(ctx context.Context) (cleanup func(), err error) {
	var wg sync.WaitGroup
	listeners := []net.Listener{}

	lc, err := c.server.LocalClient()
	if err != nil {
		return nil, err
	}

	for dbName, dbConfig := range c.config.Databases {
		relay, err := NewRelay(&dbConfig, lc)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay for %q: %w", dbName, err)
		}
		expvar.Publish(dbName, relay.Metrics())

		relayListener, err := c.server.Listen("tcp", fmt.Sprintf(":%d", dbConfig.Port))
		if err != nil {
			return nil, fmt.Errorf("failed to listen on port %d for %q: %w", dbConfig.Port, dbName, err)
		}
		listeners = append(listeners, relayListener)

		wg.Add(1)
		go func(r Relay, l net.Listener, name string) {
			defer wg.Done()
			if err := r.Serve(l); err != nil && ctx.Err() == nil {
				log.Printf("Relay for %q ended: %v", name, err)
			}
		}(relay, relayListener, dbName)
	}

	cleanup = func() {
		for _, l := range listeners {
			l.Close()
		}
		wg.Wait()
	}
	return cleanup, nil
}
