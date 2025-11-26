package internal

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/openbao/openbao/plugins/database/postgresql"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*pgWireRelay)(nil)

type pgWireRelay struct {
	relay

	// TODO(max) move session data outside the relay so the same instance can serve multiple connections
	startupMessagesCache []pgproto3.BackendMessage
}

func newPGWire(dbKey string, dbCfg *DBConfig, tsClient *local.Client) (*pgWireRelay, error) {
	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, err
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}
	relayCert, err := GenerateSelfSignedCert(dbCfg.Host)
	if err != nil {
		return nil, err
	}

	r := &pgWireRelay{
		relay: relay{
			dbKey:       dbKey,
			dbEngine:    dbCfg.Engine,
			dbHost:      dbCfg.Host,
			dbPort:      dbCfg.Port,
			dbAdminUser: dbCfg.AdminUser,
			dbAdminPass: dbCfg.AdminPassword,
			dbCertPool:  dbCertPool,
			relayCert:   []tls.Certificate{relayCert},
			tsClient:    tsClient,
			metrics: &relayMetrics{
				errors: metrics.LabelMap{Label: "kind"},
			},
		},
	}
	r.concrete = r

	if err = r.initSecretsEngine(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *pgWireRelay) initSecretsEngine() error {
	plugin, err := postgresql.New()
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL engine: %v", err)
	}

	secretsEngine, ok := plugin.(dbplugin.Database)
	if !ok {
		return fmt.Errorf("plugin does not implement Database interface")
	}

	// TODO(max) make the ssl mode configurable or detect the stricter mode we can use if we have a cert on hand
	connectionURL := fmt.Sprintf("postgresql://%s:%s@%s:%d/postgres?sslmode=require",
		r.dbAdminUser, r.dbAdminPass, r.dbHost, r.dbPort)

	_, err = secretsEngine.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connectionURL,
		},
		VerifyConnection: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize PostgreSQL secrets engine: %v", err)
	}

	r.secretsEngine = secretsEngine
	return nil
}

func (r *pgWireRelay) handleTLSNegotiation(ctx context.Context, tsConn net.Conn) (net.Conn, error) {
	// Read first 8 bytes to check for SSL request
	buf := make([]byte, 8)
	if _, err := io.ReadFull(tsConn, buf); err != nil {
		return nil, fmt.Errorf("reading TLS negotiation request: %w", err)
	}

	// Check if it's an SSL request (magic bytes: length=8, code=80877103)
	if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 8 &&
		buf[4] == 0x04 && buf[5] == 0xd2 && buf[6] == 0x16 && buf[7] == 0x2f {
		// Client wants TLS - send 'S' to accept
		if _, err := tsConn.Write([]byte{'S'}); err != nil {
			return nil, fmt.Errorf("sending TLS accept: %w", err)
		}

		// Perform TLS handshake using shared helper
		tlsConn := tls.Server(tsConn, &tls.Config{
			ServerName:   r.dbHost,
			Certificates: r.relayCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	// Not a TLS request - return buffered connection with the bytes we already read
	return NewBufferedConn(tsConn, buf), nil
}

func (r *pgWireRelay) parseHandshake(_ context.Context, conn net.Conn) (string, string, map[string]string, error) {
	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	if err != nil {
		r.relay.metrics.errors.Add("startup-message", 1)
		return "", "", nil, fmt.Errorf("receiving startup message: %w", err)
	}

	var params map[string]string
	switch msg := startupMsg.(type) {
	case *pgproto3.StartupMessage:
		params = msg.Parameters
	case *pgproto3.SSLRequest:
		return "", "", nil, fmt.Errorf("unexpected SSL request after negotiation")
	default:
		return "", "", nil, fmt.Errorf("unexpected startup message type: %T", msg)
	}

	username := params["user"]
	database := params["database"]
	if database == "" {
		database = username
	}

	return username, database, params, nil
}

func (r *pgWireRelay) createSessionUser(ctx context.Context) error {
	generatedPassword, err := GenerateSecurePassword()
	if err != nil {
		r.relay.metrics.errors.Add("password-generation-failed", 1)
		return err
	}

	creationStatements := dbplugin.Statements{
		Commands: []string{
			fmt.Sprintf(`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`),
			fmt.Sprintf(`GRANT "%s" TO "{{name}}";`, r.targetRole),
		},
	}

	usernameConfig := dbplugin.UsernameMetadata{
		DisplayName: r.targetRole,
		RoleName:    r.targetRole,
	}

	expiration := time.Now().Add(24 * time.Hour) // TODO make permanent once we know we garbage collect correctly
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: usernameConfig,
		Statements:     creationStatements,
		Expiration:     expiration,
		CredentialType: dbplugin.CredentialTypePassword,
		Password:       generatedPassword,
	}

	resp, err := r.secretsEngine.NewUser(ctx, newUserReq)
	if err != nil {
		r.relay.metrics.errors.Add("plugin-newuser-failed", 1)
		return fmt.Errorf("failed to generate credentials for role %s: %v", r.targetRole, err)
	}

	r.sessionRole = resp.Username
	r.sessionPassword = generatedPassword

	return nil
}

func (r *pgWireRelay) deleteSessionUser(ctx context.Context) error {
	if r.sessionRole == "" {
		return nil
	}

	deleteReq := dbplugin.DeleteUserRequest{
		Username: r.sessionRole,
		Statements: dbplugin.Statements{
			Commands: []string{
				fmt.Sprintf(`REVOKE "%s" FROM "{{name}}";`, r.targetRole),
				`DROP ROLE IF EXISTS "{{name}}";`,
			},
		},
	}

	_, err := r.secretsEngine.DeleteUser(ctx, deleteReq)
	if err != nil {
		r.relay.metrics.errors.Add("revoke-credentials-failed", 1)
		return err
	}

	return nil
}

func (r *pgWireRelay) connectToDatabase(ctx context.Context, clientParams map[string]string) (net.Conn, error) {
	// Dial the database
	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", r.dbHost, r.dbPort))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Send SSL request to database
	sslReq := &pgproto3.SSLRequest{}
	buf, encodeErr := sslReq.Encode(nil)
	if encodeErr != nil {
		dbConn.Close()
		return nil, fmt.Errorf("encoding SSL request: %w", encodeErr)
	}
	if _, err := dbConn.Write(buf); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("sending SSL request: %w", err)
	}

	// Read SSL response
	response := make([]byte, 1)
	if _, err := io.ReadFull(dbConn, response); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("reading SSL response: %w", err)
	}

	if response[0] != 'S' {
		dbConn.Close()
		return nil, fmt.Errorf("database rejected SSL")
	}

	// Upgrade to TLS
	tlsConn := tls.Client(dbConn, &tls.Config{
		ServerName: r.dbHost,
		RootCAs:    r.dbCertPool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Create frontend for communication (relay acts as client to the database)
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(tlsConn), tlsConn)

	// Send startup message with our ephemeral credentials
	startupParams := map[string]string{
		"user":     r.sessionRole,
		"database": r.sessionDatabase,
	}
	// Copy other parameters from client (like application_name, client_encoding, etc.)
	for k, v := range clientParams {
		if k != "user" && k != "database" {
			startupParams[k] = v
		}
	}

	startup := &pgproto3.StartupMessage{
		ProtocolVersion: 196608, // version 3.0
		Parameters:      startupParams,
	}
	startupBuf, encodeErr := startup.Encode(nil)
	if encodeErr != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("encoding startup message: %w", encodeErr)
	}
	if _, err := tlsConn.Write(startupBuf); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("sending startup message: %w", err)
	}

	// Handle authentication - but don't wait for ReadyForQuery
	// We'll forward those messages to the client later
	if err := r.handleUpstreamAuth(frontend); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("authentication: %w", err)
	}

	return tlsConn, nil
}

func (r *pgWireRelay) sendAuthSuccessToClient(conn net.Conn) error {
	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	if err := clientBackend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return fmt.Errorf("sending auth ok to client: %w", err)
	}

	for _, msg := range r.startupMessagesCache {
		if err := clientBackend.Send(msg); err != nil {
			return fmt.Errorf("sending startup message to client: %w", err)
		}
	}

	return nil
}

func (r *pgWireRelay) proxyConnection(clientConn, dbConn net.Conn, auditFile *os.File) error {
	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	dbFrontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(dbConn), dbConn)

	errc := make(chan error, 2)

	go func() {
		errc <- r.proxyClientToDatabase(clientBackend, dbFrontend, auditFile)
	}()

	go func() {
		errc <- r.proxyDatabaseToClient(dbFrontend, clientBackend)
	}()

	return <-errc
}

func (r *pgWireRelay) proxyClientToDatabase(clientBackend *pgproto3.Backend, dbFrontend *pgproto3.Frontend, auditFile *os.File) error {
	for {
		msg, err := clientBackend.Receive()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if err.Error() == "unexpected EOF" {
				return nil
			}
			return fmt.Errorf("error receiving from client: %w", err)
		}

		if auditFile != nil {
			if query, ok := msg.(*pgproto3.Query); ok {
				auditQuery(auditFile, query.String)
			}
		}

		if err := dbFrontend.Send(msg); err != nil {
			return fmt.Errorf("error sending to database: %w", err)
		}
	}
}

func (r *pgWireRelay) proxyDatabaseToClient(dbFrontend *pgproto3.Frontend, clientBackend *pgproto3.Backend) error {
	for {
		msg, err := dbFrontend.Receive()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if err.Error() == "unexpected EOF" {
				return nil
			}
			return fmt.Errorf("error receiving from database: %w", err)
		}

		if err := clientBackend.Send(msg); err != nil {
			return fmt.Errorf("error sending to client: %w", err)
		}
	}
}

func (r *pgWireRelay) handleUpstreamAuth(frontend *pgproto3.Frontend) error {
	md5Hash := func(s string) string {
		hash := md5.Sum([]byte(s))
		return hex.EncodeToString(hash[:])
	}

	authenticated := false
	r.startupMessagesCache = make([]pgproto3.BackendMessage, 0)

	for {
		msg, err := frontend.Receive()
		if err != nil {
			return fmt.Errorf("receiving auth message: %w", err)
		}

		switch msg := msg.(type) {
		case *pgproto3.AuthenticationOk:
			authenticated = true

		case *pgproto3.AuthenticationCleartextPassword:
			pwdMsg := &pgproto3.PasswordMessage{Password: r.sessionPassword}
			if err := frontend.Send(pwdMsg); err != nil {
				return fmt.Errorf("sending password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			md5Pwd := "md5" + md5Hash(md5Hash(r.sessionPassword+r.sessionRole)+string(msg.Salt[:]))
			pwdMsg := &pgproto3.PasswordMessage{Password: md5Pwd}
			if err := frontend.Send(pwdMsg); err != nil {
				return fmt.Errorf("sending MD5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			if err := r.handleSCRAMAuth(frontend, msg.AuthMechanisms); err != nil {
				return fmt.Errorf("SCRAM auth: %w", err)
			}

		case *pgproto3.ErrorResponse:
			return fmt.Errorf("database error: %s: %s", msg.Code, msg.Message)

		case *pgproto3.ParameterStatus, *pgproto3.BackendKeyData:
			if authenticated {
				r.startupMessagesCache = append(r.startupMessagesCache, msg)
			}

		case *pgproto3.ReadyForQuery:
			if authenticated {
				r.startupMessagesCache = append(r.startupMessagesCache, msg)
				return nil
			}
			return fmt.Errorf("unexpected ReadyForQuery before authentication")

		default:
			if authenticated {
				return fmt.Errorf("unexpected message after auth: %T", msg)
			}
			return fmt.Errorf("unexpected message during auth: %T", msg)
		}
	}
}

func (r *pgWireRelay) handleSCRAMAuth(frontend *pgproto3.Frontend, mechanisms []string) error {
	supportsSHA256 := false
	for _, mech := range mechanisms {
		if mech == "SCRAM-SHA-256" {
			supportsSHA256 = true
			break
		}
	}
	if !supportsSHA256 {
		return fmt.Errorf("server doesn't support SCRAM-SHA-256")
	}

	scram, err := NewSCRAMConversation(r.sessionRole, r.sessionPassword)
	if err != nil {
		return err
	}

	clientFirst, err := scram.ClientFirst()
	if err != nil {
		return err
	}

	saslInitial := &pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(clientFirst),
	}
	if err := frontend.Send(saslInitial); err != nil {
		return fmt.Errorf("sending SCRAM initial response: %w", err)
	}

	msg, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("receiving SCRAM server-first: %w", err)
	}

	saslContinue, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", msg)
	}

	clientFinal, err := scram.ClientFinal(string(saslContinue.Data))
	if err != nil {
		return err
	}

	saslResponse := &pgproto3.SASLResponse{
		Data: []byte(clientFinal),
	}
	if err := frontend.Send(saslResponse); err != nil {
		return fmt.Errorf("sending SCRAM response: %w", err)
	}

	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("receiving SCRAM server-final: %w", err)
	}

	switch msg := msg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		return scram.VerifyServerFinal(string(msg.Data))

	case *pgproto3.ErrorResponse:
		return fmt.Errorf("SCRAM auth failed: %s: %s", msg.Code, msg.Message)

	default:
		return fmt.Errorf("unexpected message during SCRAM final: %T", msg)
	}
}
