package internal

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tailscale/ts-db-connector/testutil"
	"github.com/tailscale/ts-db-connector/testutil/cockroachdb"
	"github.com/tailscale/ts-db-connector/testutil/postgres"
	"github.com/tailscale/ts-db-connector/testutil/tailscale"
	"tailscale.com/types/key"
)

const ACCTEST_TIMEOUT = 120 * time.Second

func TestMain(m *testing.M) {
	// Disable ryuk to avoid the overhead of running another container on every test run.
	// It isn't required, as we're already running the container cleanup with defer on exit.
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	os.Exit(m.Run())
}

func TestPostgresRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), ACCTEST_TIMEOUT)
	defer cancel()

	// =====
	// GIVEN
	// =====

	control := setupControl(t)

	dbInstance := "my-postgres-1"
	dbName := "testdb"
	adminUser := "admin"
	adminPassword := "admin123"
	clientRole := "testrole"

	certDir, CAFile := postgres.SetupDBCerts(t)
	host, port, cleanup := postgres.StartPostgres(t, ctx, certDir, dbName, adminUser, adminPassword, clientRole)
	defer cleanup()
	configJSON := formatConfigJSON(t, "postgres", dbInstance, host, port, CAFile, adminUser, adminPassword)
	appCap := formatAppCap(t, "postgres", dbInstance, dbName, clientRole)

	connectorTsnet, connectorIP, connectorNodeKey := tailscale.StartTsnetServer(t, ctx, control.URL, "test-db-connector")
	defer connectorTsnet.Close()
	clientTsnet, clientIP, clientNodeKey := tailscale.StartTsnetServer(t, ctx, control.URL, "test-db-client")
	defer clientTsnet.Close()
	control.grantAppCap(appCap, clientIP, clientNodeKey, connectorIP, connectorNodeKey)
	defer control.revokeAllGrants(clientIP, clientNodeKey, connectorIP, connectorNodeKey)

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
	t.Logf("Expect an SSL EOF below on success because dial doesn't respect the PGWire protocol.")
	tailscale.AssertCanDialNode(t, ctx, clientTsnet, connectorIP, port)

	// Run the actual tests that check the client can run various queries via the connector.
	db := testutil.MustOpenPGWireCompatibleDB(t, clientTsnet, connectorIP, port, dbName, clientRole)
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

func TestCockroachDBRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), ACCTEST_TIMEOUT)
	defer cancel()

	// =====
	// GIVEN
	// =====

	control := setupControl(t)

	dbInstance := "my-cockroach-1"
	dbName := "testdb"
	adminUser := "cockroach_admin"
	adminPassword := "admin123"
	clientRole := "testrole"

	certDir, CAFile := cockroachdb.SetupDBCerts(t)
	host, port, cleanup := cockroachdb.StartCockroachDB(t, ctx, certDir, dbName, adminUser, adminPassword, clientRole)
	defer cleanup()
	configJSON := formatConfigJSON(t, "cockroachdb", dbInstance, host, port, CAFile, adminUser, adminPassword)
	appCap := formatAppCap(t, "cockroachdb", dbInstance, dbName, clientRole)

	connectorTsnet, connectorIP, connectorNodeKey := tailscale.StartTsnetServer(t, ctx, control.URL, "test-db-connector")
	defer connectorTsnet.Close()
	clientTsnet, clientIP, clientNodeKey := tailscale.StartTsnetServer(t, ctx, control.URL, "test-db-client")
	defer clientTsnet.Close()
	control.grantAppCap(appCap, clientIP, clientNodeKey, connectorIP, connectorNodeKey)
	defer control.revokeAllGrants(clientIP, clientNodeKey, connectorIP, connectorNodeKey)

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
	t.Logf("Expect an SSL EOF below on success because dial doesn't respect the PGWire protocol.")
	tailscale.AssertCanDialNode(t, ctx, clientTsnet, connectorIP, port)

	// Run the actual tests that check the client can run various queries via the connector.
	db := testutil.MustOpenPGWireCompatibleDB(t, clientTsnet, connectorIP, port, dbName, clientRole)
	defer db.Close()
	queryCtx, queryCancel := context.WithTimeout(ctx, 2*time.Second)
	defer queryCancel()

	var version string
	if err := db.QueryRowContext(queryCtx, "SELECT version()").Scan(&version); err != nil {
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

type controlFixture struct {
	URL             string
	grantAppCap     func(appCap map[string]any, clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic)
	revokeAllGrants func(clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic)
}

func setupControl(t *testing.T) controlFixture {
	testutil.SkipUnlessAcc(t)

	controlURL := os.Getenv("TEST_CONTROL_URL")
	apiKey := os.Getenv("TEST_APIKEY")

	if controlURL == "" {
		t.Log("TEST_CONTROL_URL environment variable is empty, running acceptance test against testcontrol server")
		fakeControlUrl, control := tailscale.FakeControlStart(t)
		return controlFixture{
			URL: fakeControlUrl,
			grantAppCap: func(appCap map[string]any, clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic) {
				tailscale.FakeControlGrantAppCap(t, appCap, clientIP, clientNodeKey, connectorIP, connectorNodeKey, control)
			},
			revokeAllGrants: func(clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic) {
				// This is a no op for now because that fake control starts with a clean slate for each test.
			},
		}
	}

	if apiKey == "" {
		t.Fatal("TEST_CONTROL_URL environment variable is set, but TEST_APIKEY is empty.")
	}

	t.Logf("Running acceptance test against TEST_CONTROL_URL=%s", controlURL)
	return controlFixture{
		URL: controlURL,
		grantAppCap: func(appCap map[string]any, clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic) {
			tailscale.ControlGrantAppCap(t, clientIP, connectorIP, appCap, controlURL, apiKey)
		},
		revokeAllGrants: func(clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic) {
			tailscale.ControlRevokeAllGrants(t, clientIP, connectorIP, controlURL, apiKey)
		},
	}
}

func formatConfigJSON(t *testing.T, engine string, instance string, host string, port int, caFile string, adminUser string, adminPassword string) string {
	t.Helper()

	configJSON := fmt.Sprintf(`{
        "databases": {
            %q: {
                "engine": %q,
                "host": %q,
                "port": %d,
                "ca_file": %q,
                "admin_user": %q,
                "admin_password": %q
            }
        }
    }`, instance, engine, host, port, caFile, adminUser, adminPassword)
	return configJSON
}

func formatAppCap(t *testing.T, engine string, instance string, db string, role string) map[string]any {
	t.Helper()

	return map[string]any{
		instance: dbCapability{
			Engine: engine,
			Access: []accessSchema{
				{
					Databases: []string{db},
					Roles:     []string{role},
				},
			},
		},
	}
}
