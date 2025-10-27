package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/openbao/openbao/plugins/database/postgresql"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*pgWireWithPgProtoRelay)(nil)

type pgWireWithPgProtoRelay struct {
	base

	dbType         DBType
	dbAddr         string
	dbHost         string
	dbPort         string
	dbAdminUser    string
	dbAdminPass    string
	dbCertPool     *x509.CertPool
	downstreamCert []tls.Certificate

	sessionDatabase string
	sessionRole     string
	sessionPassword string
}

func newPGWireWithPgProtoRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (*pgWireWithPgProtoRelay, error) {
	dbHost, dbPort, err := net.SplitHostPort(dbCfg.Address)
	if err != nil {
		return nil, err
	}

	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, err
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}
	downstreamCert, err := mkSelfSigned(dbHost)
	if err != nil {
		return nil, err
	}

	r := &pgWireWithPgProtoRelay{
		dbType:         dbCfg.Type,
		dbAddr:         dbCfg.Address,
		dbHost:         dbHost,
		dbPort:         dbPort,
		dbAdminUser:    dbCfg.AdminUser,
		dbAdminPass:    dbCfg.AdminPassword,
		dbCertPool:     dbCertPool,
		downstreamCert: []tls.Certificate{downstreamCert},
	}

	r.base = base{
		initPlugin: r.initPlugin,
		serve:      r.serve,
		tsClient:   tsClient,
		metrics: &relayMetrics{
			errors: metrics.LabelMap{Label: "kind"},
		},
	}

	return r, nil
}

func (r *pgWireWithPgProtoRelay) initPlugin() error {
	pluginInterface, err := postgresql.New()
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL plugin: %v", err)
	}

	plugin, ok := pluginInterface.(dbplugin.Database)
	if !ok {
		return fmt.Errorf("plugin does not implement Database interface")
	}

	connectionURL := fmt.Sprintf("postgresql://%s:%s@%s:%s/postgres?sslmode=require",
		r.dbAdminUser, r.dbAdminPass, r.dbHost, r.dbPort)

	_, err = plugin.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connectionURL,
		},
		VerifyConnection: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize PostgreSQL plugin: %v", err)
	}

	r.plugin = plugin
	return nil
}

func (r *pgWireWithPgProtoRelay) serve(tsConn net.Conn) error {
	defer tsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create upstream and downstream connections so the relay can:
	// * impersonate a database user from the Tailscale identity
	// * audit incoming queries
	// * forward traffic between the client and the database
	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.Dial("tcp", r.dbAddr)
	defer dbConn.Close()
	if err != nil {
		r.base.metrics.errors.Add("database-connection", 1)
		return fmt.Errorf("upstream dial: %v", err)
	}

	clientBackend, clientTLSConn, dbFrontend, dbTLSConn, err := r.establishTLSConnections(tsConn, dbConn)
	if err != nil {
		return fmt.Errorf("establish TLS connections: %v", err)
	}

	// After negotiating TLS, read the next startup message
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("receive startup after TLS: %v", err)
	}
	fmt.Printf("Startup message received\n")
	r.sessionRole = startupMsg.(*pgproto3.StartupMessage).Parameters["user"]
	r.sessionDatabase = startupMsg.(*pgproto3.StartupMessage).Parameters["database"]

	user, machine, err := r.authorizeTailscaleUser(ctx, clientTLSConn)
	if err != nil {
		r.base.metrics.errors.Add("authentication", 1)
		return err
	}
	fmt.Println("Tailscale user is allowed.")

	// Tailnet user is allowed, generate and authenticate via an ephemeral user for the session
	err = r.seedCredentials(ctx)
	if err != nil {
		r.base.metrics.errors.Add("seed-credentials", 1)
		return err
	}
	defer r.revokeCredentials(ctx)

	// Now send the startup message over the encrypted connection
	err = r.sendHijackedStartupMessage(dbFrontend)
	if err != nil {
		return err
	}
	fmt.Println("Hijacked startup message written to database.")

	// Send message to database to authenticate
	if err = r.interceptAuthAndInjectPassword(clientBackend, dbFrontend, r.sessionRole, r.sessionPassword); err != nil {
		r.base.metrics.errors.Add("inject-credentials", 1)
		return err
	}
	fmt.Println("Auth intercepted.")

	if err = r.forwardInitialServerMessages(clientBackend, dbFrontend); err != nil {
		r.base.metrics.errors.Add("wait-for-readiness", 1)
		return err
	}
	fmt.Println("DB ready for queries.")

	// Create audit file for this session
	auditFile, err := createAuditFile(user, machine, string(r.dbType), r.dbHost, r.sessionDatabase, r.sessionRole)
	if err != nil {
		r.base.metrics.errors.Add("audit-file-create-failed", 1)
		return fmt.Errorf("failed to create audit file: %v", err)
	}
	defer auditFile.Close()

	// Impersonation all set, just relay the traffic as long as the connection is alive
	r.base.metrics.startedSessions.Add(1)
	r.base.metrics.activeSessions.Add(1)
	defer r.base.metrics.activeSessions.Add(-1)

	errc := make(chan error, 2)

	// client -> backend (intercept frontend messages)
	go func() {
		for {
			// Receive client message
			msg, err := clientBackend.Receive()
			if err != nil {
				errc <- fmt.Errorf("receive from client: %w", err)
				return
			}
			// Log queries in audit file
			if q, ok := msg.(*pgproto3.Query); ok {
				if _, err := auditFile.WriteString(fmt.Sprintf("client query: %s\n", q.String)); err != nil {
					errc <- fmt.Errorf("audit file write: %v", err)
				}
			}

			// Forward to backend server
			dbFrontend.Send(msg)
			if err := dbFrontend.Flush(); err != nil {
				errc <- fmt.Errorf("flush to backend: %w", err)
				return
			}
		}
	}()

	// backend -> client (relay backend messages)
	go func() {
		backendReader := pgproto3.NewFrontend(dbTLSConn, dbTLSConn)
		for {
			msg, err := backendReader.Receive()
			if err != nil {
				errc <- fmt.Errorf("receive from backend: %w", err)
				return
			}

			// send to client using clientBackend to correctly frame messages (expects BackendMessage)
			clientBackend.Send(msg)
			if err := clientBackend.Flush(); err != nil {
				errc <- fmt.Errorf("flush to client: %w", err)
				return
			}
		}
	}()

	// Wait for an error from either direction
	if err := <-errc; err != nil {
		return fmt.Errorf("connection error: %v", err)
	}

	return nil
}

// Verify access based on Tailscale identity and capabilities
func (r *pgWireWithPgProtoRelay) authorizeTailscaleUser(ctx context.Context, clientTLSConn net.Conn) (string, string, error) {
	user, machine, capabilities, err := r.getClientIdentity(ctx, clientTLSConn)
	if err != nil {
		return "", "", err
	}

	allowed, err := r.hasAccess(user, machine, string(r.dbType), r.sessionDatabase, r.sessionRole, capabilities)
	if err != nil {
		return "", "", err
	}
	if !allowed {
		return "", "", err
	}
	return user, machine, nil
}

func (r *pgWireWithPgProtoRelay) seedCredentials(ctx context.Context) error {
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		r.base.metrics.errors.Add("password-generation-failed", 1)
		return fmt.Errorf("failed to generate random password: %v", err)
	}
	generatedPassword := hex.EncodeToString(passwordBytes)

	creationStatements := dbplugin.Statements{
		Commands: []string{
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			fmt.Sprintf(`GRANT "%s" TO "{{name}}";`, r.sessionRole),
		},
	}

	usernameConfig := dbplugin.UsernameMetadata{
		DisplayName: r.sessionRole,
		RoleName:    r.sessionRole,
	}

	expiration := time.Now().Add(24 * time.Hour) // TODO should we disable expiration and just keep credentials for the duration of a session?
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig,
		Statements:     creationStatements,
		Expiration:     expiration,
		CredentialType: dbplugin.CredentialTypePassword,
		Password:       generatedPassword,
	}

	resp, err := r.plugin.NewUser(ctx, newUserReq)
	if err != nil {
		r.base.metrics.errors.Add("plugin-newuser-failed", 1)
		return fmt.Errorf("failed to generate credentials for role %s: %v", r.sessionRole, err)
	}

	r.sessionRole = resp.Username
	r.sessionPassword = generatedPassword

	return nil
}

func (r *pgWireWithPgProtoRelay) revokeCredentials(ctx context.Context) {
	if r.sessionRole == "" {
		return
	}

	deleteReq := dbplugin.DeleteUserRequest{
		Username: r.sessionRole,
		Statements: dbplugin.Statements{
			Commands: []string{
				fmt.Sprintf(`REVOKE "%s" FROM "{{name}}";`, r.sessionRole),
				`DROP ROLE IF EXISTS "{{name}}";`,
			},
		},
	}

	_, err := r.plugin.DeleteUser(ctx, deleteReq)
	if err != nil {
		r.base.metrics.errors.Add("revoke-credentials-failed", 1)
	}
}

func (r *pgWireWithPgProtoRelay) establishTLSConnections(tsConn net.Conn, dbConn net.Conn) (*pgproto3.Backend, net.Conn, *pgproto3.Frontend, *tls.Conn, error) {
	// Create front/backend protocol handlers.
	clientBackend := pgproto3.NewBackend(tsConn, tsConn) // will speak backend messages to client
	dbFrontend := pgproto3.NewFrontend(dbConn, dbConn)   // will speak frontend messages to DB server

	// Handle startup and SSL negotiation from client first.
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("receive startup: %v", err)
	}
	fmt.Printf("Startup and SSL negotiation from client handled.\n")

	sm := startupMsg.(*pgproto3.SSLRequest)
	_ = sm
	// Accept SSL
	_, err = tsConn.Write([]byte("S"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("write SSL accept: %v", err)
	}
	fmt.Printf("SSL accepted written to client\n")

	tlsConfig := &tls.Config{
		ServerName:   r.dbHost,
		Certificates: r.downstreamCert,
		MinVersion:   tls.VersionTLS12,
	}
	tlsConn := tls.Server(tsConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tls handshake: %v", err)
	}
	fmt.Printf("Handshake performed\n")

	// replace clientConn and clientBackend with TLS versions
	tsConn = tlsConn
	clientBackend = pgproto3.NewBackend(tsConn, tsConn)

	// Send SSL request to database
	dbFrontend.Send(&pgproto3.SSLRequest{})
	if err := dbFrontend.Flush(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error sending start-ssl request: %v", err)
	}
	fmt.Printf("Start-ssl request sent to backend\n")

	// Read SSL response from database
	var sslResponse [1]byte
	if _, err := io.ReadFull(dbConn, sslResponse[:]); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error reading database SSL response: %v", err)
	}

	if sslResponse[0] != 'S' {
		return nil, nil, nil, nil, fmt.Errorf("database rejected SSL request, responded with %q", sslResponse[0])
	}
	fmt.Printf("Database accepted SSL request\n")

	// Upgrade database connection to TLS
	dbTLSConfig := &tls.Config{
		ServerName: r.dbHost,
		RootCAs:    r.dbCertPool,
		MinVersion: tls.VersionTLS12,
	}
	dbTLSConn := tls.Client(dbConn, dbTLSConfig)
	if err := dbTLSConn.Handshake(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("database TLS handshake failed: %v", err)
	}
	fmt.Printf("Database TLS handshake completed\n")

	// Replace the backend frontend with TLS connection
	dbFrontend = pgproto3.NewFrontend(dbTLSConn, dbTLSConn)
	return clientBackend, tsConn, dbFrontend, dbTLSConn, nil
}

func (r *pgWireWithPgProtoRelay) sendHijackedStartupMessage(dbFrontend *pgproto3.Frontend) error {
	dbFrontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     r.sessionRole,
			"database": r.sessionDatabase,
		},
	})
	if err := dbFrontend.Flush(); err != nil {
		return fmt.Errorf("error sending startup message: %v", err)
	}
	return nil
}

func (r *pgWireWithPgProtoRelay) forwardInitialServerMessages(clientBackend *pgproto3.Backend, dbFrontend *pgproto3.Frontend) error {
	for {
		// Receive message from DB
		msg, err := dbFrontend.Receive()
		if err != nil {
			return err
		}

		// Forward message to client
		clientBackend.Send(msg)
		err = clientBackend.Flush()
		if err != nil {
			return err
		}

		// Until DB signals it's ready for query
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return nil
		}
	}
}

func (r *pgWireWithPgProtoRelay) interceptAuthAndInjectPassword(clientBackend *pgproto3.Backend, dbFrontend *pgproto3.Frontend, role string, password string) error {
	msg, err := dbFrontend.Receive()
	if err != nil {
		return fmt.Errorf("read upstream auth req: %w", err)
	}
	switch msgType := msg.(type) {
	case *pgproto3.AuthenticationCleartextPassword: // ok
	case *pgproto3.AuthenticationMD5Password: // ok
	default:
		return fmt.Errorf("expected upstream AuthenticationRequest 'R' for cleartext or MD5 password, got %q", msgType)
	}

	// ---- DON'T forward the request to client ----
	// Instead, immediately tell the client "auth succeeded".
	clientBackend.Send(&pgproto3.AuthenticationOk{})
	err = clientBackend.Flush()
	if err != nil {
		return fmt.Errorf("send fake auth ok to client: %w", err)
	}

	switch msgType := msg.(type) {
	case *pgproto3.AuthenticationCleartextPassword:
		dbFrontend.Send(&pgproto3.PasswordMessage{Password: password})
		if err := dbFrontend.Flush(); err != nil {
			return fmt.Errorf("send upstream cleartext pw: %w", err)
		}
		fmt.Printf("Sent cleartext password\n")
	case *pgproto3.AuthenticationMD5Password:
		q, _ := msg.(*pgproto3.AuthenticationMD5Password)
		digestedPassword := md5Response(password, role, q.Salt)
		dbFrontend.Send(&pgproto3.PasswordMessage{
			Password: digestedPassword,
		})
		if err := dbFrontend.Flush(); err != nil {
			return fmt.Errorf("send upstream md5 pw: %w", err)
		}
		fmt.Printf("Sent md5 password\n")
	// TODO support other auth types such as SCRAM
	default:
		return fmt.Errorf("unsupported upstream auth type %q", msgType)
	}

	// Drain upstream messages until AuthenticationOk
	for {
		msg, err := dbFrontend.Receive()
		if err != nil {
			return fmt.Errorf("read upstream post-auth: %w", err)
		}
		switch msg.(type) {
		case *pgproto3.AuthenticationOk:
			// Upstream auth ok. We already told client it’s ok, so just ignore.
			return nil
		case *pgproto3.AuthenticationCleartextPassword,
			*pgproto3.AuthenticationMD5Password,
			*pgproto3.AuthenticationGSS,
			*pgproto3.AuthenticationGSSContinue,
			*pgproto3.AuthenticationSASL,
			*pgproto3.AuthenticationSASLContinue,
			*pgproto3.AuthenticationSASLFinal:
			return fmt.Errorf("unexpected extra auth step from upstream")
		case *pgproto3.ErrorResponse:
			clientBackend.Send(&pgproto3.ErrorResponse{})
			_ = clientBackend.Flush()
			return fmt.Errorf("upstream auth error")
		default:
			clientBackend.Send(msg)
			if err := clientBackend.Flush(); err != nil {
				return fmt.Errorf("forward upstream msg: %w", err)
			}
		}
	}
}
