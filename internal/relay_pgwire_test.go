package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tailscale/ts-db-connector/testutil"
	"github.com/tailscale/ts-db-connector/testutil/postgres"
	"github.com/tailscale/ts-db-connector/testutil/tailscale"
	"tailscale.com/tailcfg"
)

func TestRelayServe(t *testing.T) {
	testutil.SkipUnlessAcc(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Disable ryuk to avoid the overhead of running another container on every test run.
	// It isn't required, as we're already running the container cleanup with defer on exit.
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	// =====
	// GIVEN
	// =====

	pgInstance := "my-postgres-1"
	pgDb := "testdb"
	pgAdminUser := "admin"
	pgAdminPassword := "admin123"
	pgRole := "testrole"

	pgCertDir, pgCAFile := postgres.SetupPostgresCerts(t, "localhost", "postgres-db")
	pgHost, pgPort, pgCleanup := postgres.StartPostgres(t, ctx, pgCertDir, pgDb, pgAdminUser, pgAdminPassword, pgRole)
	defer pgCleanup(t, ctx)
	controlURL, control := tailscale.StartControl(t)
	connectorTsnet, connectorIP, connectorNodeKey := tailscale.StartTsnetServer(t, ctx, controlURL, "test-db-connector")
	defer connectorTsnet.Close()
	clientTsnet, clientIP, clientNodeKey := tailscale.StartTsnetServer(t, ctx, controlURL, "test-db-client")
	defer clientTsnet.Close()

	configJSON := formatConfigJSON(pgInstance, pgHost, pgPort, pgCAFile, pgAdminUser, pgAdminPassword)
	pgAppCap := formatAppCap(t, pgInstance, pgDb, pgPort, pgRole)
	filterRules := formatFilterRules(clientIP, connectorIP, pgAppCap)
	tailscale.MustInjectFilterRules(t, control, connectorNodeKey, clientNodeKey, filterRules...)
	tailscale.MustInjectFilterRules(t, control, clientNodeKey, connectorNodeKey)

	// ====
	// WHEN
	// ====

	config, err := ParseConfig([]byte(configJSON))
	if err != nil {
		t.Fatal(err)
	}
	connector := &Connector{
		config: config,
	}
	if err := connector.Run(ctx, connectorTsnet); err != nil {
		t.Fatal(err)
	}

	// ====
	// THEN
	// ====

	// Perform sanity checks of the connection between client and connector on tsnet level.
	tailscale.AssertCanPingNode(t, ctx, clientTsnet, connectorIP)
	tailscale.AssertCanDialNode(t, ctx, clientTsnet, connectorIP, pgPort)

	// Run the actual tests that check the client can run various queries via the connector.
	// TODO: Might not all be needed?

	db := postgres.MustOpenPostgresDB(t, clientTsnet, connectorIP, pgPort, pgDb, pgRole)
	defer db.Close()
	queryCtx, queryCancel := context.WithTimeout(ctx, 2*time.Second)
	defer queryCancel()

	var version string
	if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
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
		t.Fatalf("expected name 'test_value', got '%s'", name)
	}

	t.Logf("Successfully inserted and queried database via connector")
}

func formatConfigJSON(pgInstance string, pgHost string, pgPort int, pgCAFile string, pgAdminUser string, pgAdminPassword string) string {
	configJSON := fmt.Sprintf(`{
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
	return configJSON
}

func formatAppCap(t *testing.T, pgInstance string, pgDB string, pgPort int, pgRole string) string {
	t.Helper()

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
		t.Fatalf("failed to marshal capability: %v", err)
	}

	return fmt.Sprintf(`{%q: %s}`, pgInstance, capValue)
}

func formatFilterRules(clientIP netip.Addr, connectorIP netip.Addr, connectorAppCap string) []tailcfg.FilterRule {
	return []tailcfg.FilterRule{
		{
			SrcIPs: []string{clientIP.String()},
			DstPorts: []tailcfg.NetPortRange{
				{
					IP:    fmt.Sprintf("%s/32", connectorIP), // TODO: there must be a better way!?
					Ports: tailcfg.PortRange{First: 0, Last: 65535},
				},
			},
		},
		{
			SrcIPs: []string{clientIP.String()},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix(fmt.Sprintf("%s/32", connectorIP)), // TODO: there must be a better way!?
				},
				CapMap: tailcfg.PeerCapMap{
					tsDBCap: []tailcfg.RawMessage{
						tailcfg.RawMessage(connectorAppCap),
					},
				},
			}},
		},
	}
}
