package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
	"tailscale.com/tailcfg"
)

// Relay is used to proxy connections from Tailscale nodes to a database server.
//
// Uses the node's Tailscale identity to authorize access and map it
// to a database user or role, according to the grants defined in the tailnet policy file.
type Relay interface {
	// Serve listens to incoming tailscale connections on the provided listener
	// and proxies each connection to the database server in a separate session.
	Serve(net.Listener) error

	// Metrics returns metrics about the relay's operation which can be consulted on the debug endpoint.
	// Useful for monitoring and debugging.
	Metrics() expvar.Var

	// handleTLSNegotiation performs protocol-specific TLS negotiation with the client.
	handleTLSNegotiation(ctx context.Context, conn net.Conn) (net.Conn, error)

	// parseHandshake extracts authentication details from the client's initial handshake.
	// Returns the requested username, database (or default if not specified), and any additional connection parameters
	// to forward to the underlying database.
	parseHandshake(conn net.Conn) (username, database string, params map[string]string, err error)

	// createSessionUser creates a dynamic user used for the duration of the connection.
	// The user is created with the role and permissions equal to the principal being impersonated.
	createSessionUser(ctx context.Context) error

	// deleteSessionUser revokes the dynamic user created for the session.
	deleteSessionUser(ctx context.Context)

	// connectToDatabase establishes a connection to the underlying database with the dynamic user created previously.
	connectToDatabase(ctx context.Context, params map[string]string) (net.Conn, error)

	// sendAuthSuccessToClient sends a protocol-specific authentication success message to the client.
	sendAuthSuccessToClient(conn net.Conn) error

	// proxyConnection bidirectionally proxies data between client and database, with optional query auditing.
	proxyConnection(clientConn, dbConn net.Conn, auditFile *os.File) error
}

// relay provides common fields and helper methods for relay implementations.
type relay struct {
	// tsClient is the Tailscale client used for identity verification
	tsClient *local.Client
	// secretsEngine is the plugin used to manage users and credentials
	secretsEngine dbplugin.Database
	// concrete
	concrete Relay
	// metrics holds relay operation metrics
	metrics *relayMetrics

	// Common database configuration
	dbKey       string
	dbEngine    DBEngine
	dbHost      string
	dbPort      int
	dbAdminUser string
	dbAdminPass string

	// Certificates for TLS connections to the database and clients
	dbCertPool *x509.CertPool
	relayCert  []tls.Certificate

	// Session-specific fields
	// TODO(max) move session data outside the relay so the same instance can serve multiple connections
	targetRole      string
	sessionDatabase string
	sessionRole     string
	sessionPassword string
}

// relayMetrics holds metrics about the relay's operation
// which can be consulted on the debug endpoint.
type relayMetrics struct {
	// activeSessions is the number of currently active sessions.
	activeSessions expvar.Int
	// startedSessions is the total number of sessions started since the relay began running.
	startedSessions expvar.Int
	// errors is a map of error types to their number of occurrence since the relay began running.
	errors metrics.LabelMap
}

func (r *relay) Serve(tsListener net.Listener) error {
	for {
		tsConn, err := tsListener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := r.serveConnection(tsConn); err != nil {
				log.Printf("session ended with error: %v", err)
			}
		}()
	}
}

func (r *relay) Metrics() expvar.Var {
	ret := &metrics.Set{}
	ret.Set("sessions_active", &r.metrics.activeSessions)
	ret.Set("sessions_started", &r.metrics.startedSessions)
	ret.Set("session_errors", &r.metrics.errors)
	return ret
}

// serveConnection handles a single database connection
func (r *relay) serveConnection(tsConn net.Conn) error {
	defer tsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientConn, err := r.concrete.handleTLSNegotiation(ctx, tsConn)
	if err != nil {
		r.metrics.errors.Add("tls-negotiation", 1)
		return fmt.Errorf("TLS negotiation: %w", err)
	}

	username, database, params, err := r.concrete.parseHandshake(clientConn)
	if err != nil {
		r.metrics.errors.Add("handshake-parse", 1)
		return fmt.Errorf("parsing handshake: %w", err)
	}

	r.targetRole = username
	r.sessionDatabase = database

	user, machine, capabilities, err := r.getClientIdentity(ctx, tsConn)
	if err != nil {
		r.metrics.errors.Add("authentication", 1)
		return err
	}

	allowed, err := r.hasAccess(user, machine, r.dbKey, string(r.dbEngine), r.sessionDatabase, r.targetRole, capabilities)
	if err != nil {
		r.metrics.errors.Add("authentication", 1)
		return err
	}
	if !allowed {
		r.metrics.errors.Add("authorization", 1)
		return fmt.Errorf("access denied for user %s to database %s as role %s", user, r.sessionDatabase, r.targetRole)
	}

	err = r.concrete.createSessionUser(ctx)
	if err != nil {
		r.metrics.errors.Add("seed-credentials", 1)
		return err
	}
	defer r.concrete.deleteSessionUser(ctx)

	dbConn, err := r.concrete.connectToDatabase(ctx, params)
	if err != nil {
		r.metrics.errors.Add("database-connection", 1)
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer dbConn.Close()

	if err := r.concrete.sendAuthSuccessToClient(clientConn); err != nil {
		r.metrics.errors.Add("auth-response", 1)
		return fmt.Errorf("sending auth success to client: %w", err)
	}

	auditFile, err := createAuditFile(user, machine, string(r.dbEngine), r.dbHost, r.sessionDatabase, "session-user")
	if err != nil {
		r.metrics.errors.Add("audit-file-create-failed", 1)
		return fmt.Errorf("failed to create audit file: %v", err)
	}
	defer auditFile.Close()

	r.metrics.startedSessions.Add(1)
	r.metrics.activeSessions.Add(1)
	defer r.metrics.activeSessions.Add(-1)

	return r.concrete.proxyConnection(clientConn, dbConn, auditFile)
}

// getClientIdentity extracts user and machine information from Tailscale WhoIs
func (r *relay) getClientIdentity(ctx context.Context, conn net.Conn) (string, string, []tailcfg.RawMessage, error) {
	whois, err := r.tsClient.WhoIs(ctx, conn.RemoteAddr().String())
	if err != nil {
		r.metrics.errors.Add("whois-failed", 1)
		return "", "", nil, fmt.Errorf("unexpected error getting client identity: %v", err)
	}

	machine := ""
	if whois.Node != nil {
		if whois.Node.Hostinfo.ShareeNode() {
			machine = "external-device"
		} else {
			machine = strings.TrimSuffix(whois.Node.Name, ".")
		}
	}

	user := ""
	if whois.UserProfile != nil {
		user = whois.UserProfile.LoginName
		if user == "tagged-devices" && whois.Node != nil {
			user = strings.Join(whois.Node.Tags, ",")
		}
	}
	if user == "" || machine == "" {
		r.metrics.errors.Add("no-ts-identity", 1)
		return "", "", nil, fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", user, machine)
	}

	return user, machine, whois.CapMap[tailcfg.PeerCapability(tsDBCap)], nil
}

// hasAccess checks if the given Tailscale identity is authorized to access the specified database
// according to the grants defined in the tailnet policy file.
func (r *relay) hasAccess(user, machine, dbKey, dbEngine, sessionDB, sessionRole string, capabilities []tailcfg.RawMessage) (bool, error) {
	if capabilities == nil {
		r.metrics.errors.Add("no-ts-db-database-capability", 1)
		return false, fmt.Errorf("user %q on machine %q does not have ts-db-database capability", user, machine)
	}

	for _, capability := range capabilities {
		var grantCap map[string]dbCapability
		if err := json.Unmarshal([]byte(capability), &grantCap); err != nil {
			r.metrics.errors.Add("capability-parse-error", 1)
			return false, fmt.Errorf("failed to parse capability value: %v", err)
		}

		for capDBKey, dbCap := range grantCap {
			if capDBKey != dbKey {
				continue
			}
			if dbCap.Engine != dbEngine {
				continue
			}

			// Check each access rule in the Access array
			for _, accessRule := range dbCap.Access {
				roleAllowed := false
				for _, allowedRole := range accessRule.Roles {
					if allowedRole == sessionRole {
						roleAllowed = true
						break
					}
				}
				if !roleAllowed {
					continue
				}

				databaseAllowed := false
				for _, allowedDB := range accessRule.Databases {
					if allowedDB == sessionDB {
						databaseAllowed = true
						break
					}
				}
				if !databaseAllowed {
					continue
				}

				return true, nil
			}
		}
	}

	r.metrics.errors.Add("not-allowed-to-impersonate", 1)
	return false, fmt.Errorf("user %q is not allowed to access database %q as role %q", user, sessionDB, sessionRole)
}
