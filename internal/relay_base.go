package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/tailscale/ts-db-connector/pkg"
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
	parseHandshake(ctx context.Context, conn net.Conn) (username, database string, params map[string]string, err error)

	// createSessionUser creates a dynamic user used for the duration of the connection.
	// The user is created with the role and permissions equal to the principal being impersonated.
	createSessionUser(ctx context.Context) error

	// deleteSessionUser revokes the dynamic user created for the session.
	deleteSessionUser(ctx context.Context) error

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
			logger := slog.With("trace_id", uuid.New().String(), "db_key", r.dbKey)
			if err := r.serveConnection(logger, tsConn); err != nil {
				var relayErr *RelayError

				if errors.As(err, &relayErr) {
					if relayErr.Underlying == nil {
						logger.Warn(relayErr.Message, "metrics_key", relayErr.Code, "origin", relayErr.Origin)
					} else {
						logger.Error(relayErr.Message, "metrics_key", relayErr.Code, "origin", relayErr.Origin, "error", relayErr.Underlying)
					}
					r.metrics.errors.Add(relayErr.Code, 1)
				} else {
					r.metrics.errors.Add("unclassified-error", 1)
					slog.Error(err.Error())
				}
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
func (r *relay) serveConnection(logger *slog.Logger, tsConn net.Conn) error {
	logger.Debug("serving new connection")
	defer tsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientConn, err := r.concrete.handleTLSNegotiation(ctx, tsConn)
	if err != nil {
		return NewError(OriginServer, "tls-negotiation", "TLS negotiation failed", err)
	}
	logger.Debug("TLS negotiation with client successful")

	username, database, params, err := r.concrete.parseHandshake(ctx, clientConn)
	if err != nil {
		return NewError(OriginServer, "handshake-parsing", "handshake parsing failed", err)
	}
	if username == "" || database == "" {
		logger.Debug("incomplete handshake details, rejecting the connection request as it appears malformed", "username", username, "database", database)
		return nil
	}
	logger.Debug("parsed client handshake", "username", username, "database", database, "params", params)

	r.targetRole = username
	r.sessionDatabase = database

	user, machine, capabilities, err := r.getClientIdentity(ctx, tsConn)
	if err != nil {
		return NewError(OriginExternal, "identity-verification", "Tailscale identity verification failed", err)
	}
	logger.Debug("Tailscale identity verification successful", "user", user, "machine", machine)

	allowed, err := r.hasAccess(r.dbKey, string(r.dbEngine), r.sessionDatabase, r.targetRole, capabilities)
	if err != nil {
		return NewError(OriginServer, "access-validation", "access validation failed", err)
	}
	if !allowed {
		return NewError(OriginClient, "access-denied", fmt.Sprintf("user %s on machine %s is not allowed to access database %q as role %q on instance %q", user, machine, r.sessionDatabase, r.targetRole, r.dbKey), nil)
	}
	logger.Debug("access granted", "user", user, "machine", machine, "database", r.sessionDatabase, "role", r.targetRole)

	err = r.concrete.createSessionUser(ctx)
	if err != nil {
		return NewError(OriginServer, "ephemeral-user-creation", "ephemeral user creation failed", err)
	}
	logger.Debug("created ephemeral user", "username", r.sessionRole)

	defer func() {
		err := r.concrete.deleteSessionUser(ctx)
		if err != nil {
			_ = NewError(OriginServer, "ephemeral-user-deletion", "failed to delete ephemeral user", err)
		}
		logger.Debug("deleted ephemeral user", "username", r.sessionRole)
	}()

	dbConn, err := r.concrete.connectToDatabase(ctx, params)
	if err != nil {
		return NewError(OriginServer, "database-connection", "database connection failed", err)
	}
	logger.Debug("connected to database", "host", r.dbHost, "port", r.dbPort)
	defer dbConn.Close()

	if err := r.concrete.sendAuthSuccessToClient(clientConn); err != nil {
		return NewError(OriginServer, "auth-response", "sending auth success to client failed", err)
	}
	logger.Debug("sent authentication success to client")

	auditFile, err := createAuditFile(user, machine, string(r.dbEngine), r.dbHost, r.sessionDatabase, r.sessionRole)
	if err != nil {
		return NewError(OriginServer, "audit-file-creation", "audit file creation failed", err)
	}
	logger.Debug("created connection audit file", "file", auditFile)
	defer auditFile.Close()

	logger.Debug("starting connection relay between client and database")
	r.metrics.startedSessions.Add(1)
	r.metrics.activeSessions.Add(1)
	defer r.metrics.activeSessions.Add(-1)

	return r.concrete.proxyConnection(clientConn, dbConn, auditFile)
}

// getClientIdentity extracts user and machine information from Tailscale WhoIs
func (r *relay) getClientIdentity(ctx context.Context, conn net.Conn) (string, string, []tailcfg.RawMessage, error) {
	whois, err := r.tsClient.WhoIs(ctx, conn.RemoteAddr().String())
	if err != nil {
		return "", "", nil, fmt.Errorf("WhoIs lookup failed: %w", err)
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
		return "", "", nil, fmt.Errorf("incomplete Tailscale identity, user %q or machine %q undefined", user, machine)
	}

	return user, machine, whois.CapMap[tailcfg.PeerCapability(pkg.TSDBCap)], nil
}

// hasAccess checks if the given Tailscale identity is authorized to access the specified database
// according to the grants defined in the tailnet policy file.
func (r *relay) hasAccess(dbKey, dbEngine, targetDB, targetRole string, capabilities []tailcfg.RawMessage) (bool, error) {
	if capabilities == nil {
		return false, nil
	}

	allowed := false
	for _, capability := range capabilities {
		var grantCap map[string]dbCapability
		if err := json.Unmarshal([]byte(capability), &grantCap); err != nil {
			return false, fmt.Errorf("capability parsing failed: %w", err)
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
					if allowedRole == targetRole {
						roleAllowed = true
						break
					}
				}
				if !roleAllowed {
					continue
				}

				databaseAllowed := false
				for _, allowedDB := range accessRule.Databases {
					if allowedDB == targetDB {
						databaseAllowed = true
						break
					}
				}
				if !databaseAllowed {
					continue
				}

				allowed = true
				break
			}
		}
	}

	return allowed, nil
}
