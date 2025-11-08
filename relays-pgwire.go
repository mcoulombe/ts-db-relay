package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/openbao/openbao/plugins/database/postgresql"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/xdg-go/scram"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*pgWireRelay)(nil)

type pgWireRelay struct {
	base

	dbEngine       DBEngine
	dbHost         string
	dbPort         int
	dbAdminUser    string
	dbAdminPass    string
	dbCertPool     *x509.CertPool
	downstreamCert []tls.Certificate

	sessionDatabase string
	sessionRole     string
	sessionPassword string
	targetRole      string
}

func newPGWireRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (*pgWireRelay, error) {
	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, err
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}
	downstreamCert, err := mkSelfSigned(dbCfg.Host)
	if err != nil {
		return nil, err
	}

	r := &pgWireRelay{
		dbEngine:       dbCfg.Engine,
		dbHost:         dbCfg.Host,
		dbPort:         dbCfg.Port,
		dbAdminUser:    dbCfg.AdminUser,
		dbAdminPass:    dbCfg.AdminPassword,
		dbCertPool:     dbCertPool,
		downstreamCert: []tls.Certificate{downstreamCert},
	}

	r.base = base{
		serve:    r.serve,
		tsClient: tsClient,
		metrics: &relayMetrics{
			errors: metrics.LabelMap{Label: "kind"},
		},
	}

	err = r.initSecretsEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database secrets engine: %v", err)
	}

	return r, nil
}

func (r *pgWireRelay) initSecretsEngine() error {
	pluginInterface, err := postgresql.New()
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL plugin: %v", err)
	}

	plugin, ok := pluginInterface.(dbplugin.Database)
	if !ok {
		return fmt.Errorf("plugin does not implement Database interface")
	}

	connectionURL := fmt.Sprintf("postgresql://%s:%s@%s:%d/postgres?sslmode=require",
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

	r.secretsEngine = plugin
	return nil
}

func (r *pgWireRelay) serve(tsConn net.Conn) error {
	defer tsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, clientConn, err := r.handleSSLNegotiation(ctx, tsConn)
	if err != nil {
		r.base.metrics.errors.Add("ssl-negotiation", 1)
		return fmt.Errorf("SSL negotiation: %w", err)
	}

	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	if err != nil {
		r.base.metrics.errors.Add("startup-message", 1)
		return fmt.Errorf("receiving startup message: %w", err)
	}

	var params map[string]string
	switch msg := startupMsg.(type) {
	case *pgproto3.StartupMessage:
		params = msg.Parameters
	case *pgproto3.SSLRequest:
		return fmt.Errorf("unexpected SSL request after negotiation")
	default:
		return fmt.Errorf("unexpected startup message type: %T", msg)
	}

	r.targetRole = params["user"]
	r.sessionDatabase = params["database"]
	if r.sessionDatabase == "" {
		r.sessionDatabase = r.targetRole
	}

	user, machine, capabilities, err := r.getClientIdentity(ctx, tsConn)
	if err != nil {
		r.base.metrics.errors.Add("authentication", 1)
		return err
	}

	allowed, err := r.hasAccess(user, machine, string(r.dbEngine), r.sessionDatabase, r.targetRole, r.dbPort, capabilities)
	if err != nil {
		r.base.metrics.errors.Add("authentication", 1)
		return err
	}
	if !allowed {
		r.base.metrics.errors.Add("authorization", 1)
		backend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
		backend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  "access denied",
		})
		return fmt.Errorf("access denied for user %s to database %s as role %s", user, r.sessionDatabase, r.targetRole)
	}

	err = r.createSessionUser(ctx)
	if err != nil {
		r.base.metrics.errors.Add("seed-credentials", 1)
		return err
	}
	defer r.deleteSessionUser(ctx)

	dbConn, dbFrontend, err := r.connectToDatabase(ctx, params)
	if err != nil {
		r.base.metrics.errors.Add("database-connection", 1)
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer dbConn.Close()

	auditFile, err := createAuditFile(user, machine, string(r.dbEngine), r.dbHost, r.sessionDatabase, r.sessionRole)
	if err != nil {
		r.base.metrics.errors.Add("audit-file-create-failed", 1)
		return fmt.Errorf("failed to create audit file: %v", err)
	}
	defer auditFile.Close()

	r.base.metrics.startedSessions.Add(1)
	r.base.metrics.activeSessions.Add(1)
	defer r.base.metrics.activeSessions.Add(-1)

	return r.proxyConnection(clientBackend, dbFrontend, auditFile)
}

func (r *pgWireRelay) createSessionUser(ctx context.Context) error {
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		r.base.metrics.errors.Add("password-generation-failed", 1)
		return fmt.Errorf("failed to generate random password: %v", err)
	}
	generatedPassword := hex.EncodeToString(passwordBytes)

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
		r.base.metrics.errors.Add("plugin-newuser-failed", 1)
		return fmt.Errorf("failed to generate credentials for role %s: %v", r.targetRole, err)
	}

	r.sessionRole = resp.Username
	r.sessionPassword = generatedPassword

	return nil
}

func (r *pgWireRelay) deleteSessionUser(ctx context.Context) {
	if r.sessionRole == "" {
		return
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
		r.base.metrics.errors.Add("revoke-credentials-failed", 1)
	}
}

// handleSSLNegotiation handles the SSL/TLS negotiation with the client
func (r *pgWireRelay) handleSSLNegotiation(ctx context.Context, tsConn net.Conn) (bool, net.Conn, error) {
	// Read first 8 bytes to check for SSL request
	buf := make([]byte, 8)
	if _, err := io.ReadFull(tsConn, buf); err != nil {
		return false, nil, fmt.Errorf("reading SSL request: %w", err)
	}

	// Check if it's an SSL request (magic bytes: length=8, code=80877103)
	if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 8 &&
		buf[4] == 0x04 && buf[5] == 0xd2 && buf[6] == 0x16 && buf[7] == 0x2f {
		// Client wants SSL - send 'S' to accept
		if _, err := tsConn.Write([]byte{'S'}); err != nil {
			return false, nil, fmt.Errorf("sending SSL accept: %w", err)
		}

		// Perform TLS handshake
		tlsConn := tls.Server(tsConn, &tls.Config{
			ServerName:   r.dbHost,
			Certificates: r.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return false, nil, fmt.Errorf("TLS handshake: %w", err)
		}
		return true, tlsConn, nil
	}

	// Not an SSL request - create a buffer reader that includes the bytes we already read
	// We need to prepend those bytes back to the connection
	bufferedConn := &bufferedConn{Conn: tsConn, buf: buf}
	return false, bufferedConn, nil
}

// connectToDatabase establishes a connection to the upstream database with our ephemeral credentials
func (r *pgWireRelay) connectToDatabase(ctx context.Context, clientParams map[string]string) (net.Conn, *pgproto3.Frontend, error) {
	// Dial the database
	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", r.dbHost, r.dbPort))
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	// Send SSL request to database
	sslReq := &pgproto3.SSLRequest{}
	buf, encodeErr := sslReq.Encode(nil)
	if encodeErr != nil {
		dbConn.Close()
		return nil, nil, fmt.Errorf("encoding SSL request: %w", encodeErr)
	}
	if _, err := dbConn.Write(buf); err != nil {
		dbConn.Close()
		return nil, nil, fmt.Errorf("sending SSL request: %w", err)
	}

	// Read SSL response
	response := make([]byte, 1)
	if _, err := io.ReadFull(dbConn, response); err != nil {
		dbConn.Close()
		return nil, nil, fmt.Errorf("reading SSL response: %w", err)
	}

	if response[0] != 'S' {
		dbConn.Close()
		return nil, nil, fmt.Errorf("database rejected SSL")
	}

	// Upgrade to TLS
	tlsConn := tls.Client(dbConn, &tls.Config{
		ServerName: r.dbHost,
		RootCAs:    r.dbCertPool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		dbConn.Close()
		return nil, nil, fmt.Errorf("TLS handshake: %w", err)
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
		return nil, nil, fmt.Errorf("encoding startup message: %w", encodeErr)
	}
	if _, err := tlsConn.Write(startupBuf); err != nil {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("sending startup message: %w", err)
	}

	// Handle authentication - but don't wait for ReadyForQuery
	// We'll forward those messages to the client later
	if err := r.handleUpstreamAuth(frontend); err != nil {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("authentication: %w", err)
	}

	return tlsConn, frontend, nil
}

// handleUpstreamAuth handles authentication with the upstream database
// Returns IMMEDIATELY after receiving AuthenticationOk, without consuming any more messages
func (r *pgWireRelay) handleUpstreamAuth(frontend *pgproto3.Frontend) error {
	md5Hash := func(s string) string {
		hash := md5.Sum([]byte(s))
		return hex.EncodeToString(hash[:])
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			return fmt.Errorf("receiving auth message: %w", err)
		}

		switch msg := msg.(type) {
		case *pgproto3.AuthenticationOk:
			// Authentication already successful
			return nil

		case *pgproto3.AuthenticationCleartextPassword:
			// Send cleartext password
			pwdMsg := &pgproto3.PasswordMessage{Password: r.sessionPassword}
			if err := frontend.Send(pwdMsg); err != nil {
				return fmt.Errorf("sending password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			// Send MD5 password
			md5Pwd := "md5" + md5Hash(md5Hash(r.sessionPassword+r.sessionRole)+string(msg.Salt[:]))
			pwdMsg := &pgproto3.PasswordMessage{Password: md5Pwd}
			if err := frontend.Send(pwdMsg); err != nil {
				return fmt.Errorf("sending MD5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			// SCRAM-SHA-256 authentication
			if err := r.handleSCRAMAuth(frontend, msg.AuthMechanisms); err != nil {
				return fmt.Errorf("SCRAM auth: %w", err)
			}

		case *pgproto3.ErrorResponse:
			return fmt.Errorf("database error: %s: %s", msg.Code, msg.Message)

		default:
			return fmt.Errorf("unexpected message during auth: %T", msg)
		}
	}
}

// handleSCRAMAuth handles SCRAM-SHA-256 authentication
func (r *pgWireRelay) handleSCRAMAuth(frontend *pgproto3.Frontend, mechanisms []string) error {
	// Check if SCRAM-SHA-256 is supported
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

	// Create SCRAM client
	scramClient, err := scram.SHA256.NewClient(r.sessionRole, r.sessionPassword, "")
	if err != nil {
		return fmt.Errorf("creating SCRAM client: %w", err)
	}
	conv := scramClient.NewConversation()

	// Send initial client message
	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM step 1: %w", err)
	}

	saslInitial := &pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(clientFirst),
	}
	if err := frontend.Send(saslInitial); err != nil {
		return fmt.Errorf("sending SCRAM initial response: %w", err)
	}

	// Receive server-first message
	msg, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("receiving SCRAM server-first: %w", err)
	}

	saslContinue, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", msg)
	}

	// Send client-final message
	clientFinal, err := conv.Step(string(saslContinue.Data))
	if err != nil {
		return fmt.Errorf("SCRAM step 2: %w", err)
	}

	saslResponse := &pgproto3.SASLResponse{
		Data: []byte(clientFinal),
	}
	if err := frontend.Send(saslResponse); err != nil {
		return fmt.Errorf("sending SCRAM response: %w", err)
	}

	// Receive server-final message
	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("receiving SCRAM server-final: %w", err)
	}

	switch msg := msg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		// Verify server signature
		_, err = conv.Step(string(msg.Data))
		if err != nil {
			return fmt.Errorf("SCRAM step 3 (verify server): %w", err)
		}
		return nil

	case *pgproto3.ErrorResponse:
		return fmt.Errorf("SCRAM auth failed: %s: %s", msg.Code, msg.Message)

	default:
		return fmt.Errorf("unexpected message during SCRAM final: %T", msg)
	}
}

// proxyConnection proxies messages between client and database with auditing
func (r *pgWireRelay) proxyConnection(clientBackend *pgproto3.Backend, dbFrontend *pgproto3.Frontend, auditFile *os.File) error {
	if err := clientBackend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return fmt.Errorf("sending auth ok to client: %w", err)
	}

	if err := r.forwardStartupMessages(dbFrontend, clientBackend); err != nil {
		return fmt.Errorf("error forwarding startup messages: %w", err)
	}

	errc := make(chan error, 2)

	// Client -> Database
	go func() {
		errc <- r.proxyClientToDatabase(clientBackend, dbFrontend, auditFile)
	}()

	// Database -> Client
	go func() {
		errc <- r.proxyDatabaseToClient(dbFrontend, clientBackend)
	}()

	// Wait for first error
	return <-errc
}

// forwardStartupMessages forwards initial parameter status and ready messages
func (r *pgWireRelay) forwardStartupMessages(dbFrontend *pgproto3.Frontend, clientBackend *pgproto3.Backend) error {
	for {
		msg, err := dbFrontend.Receive()
		if err != nil {
			return err
		}

		if err := clientBackend.Send(msg); err != nil {
			return err
		}

		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return nil
		}
	}
}

// proxyClientToDatabase forwards messages from client to database with auditing
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

// proxyDatabaseToClient forwards messages from database to client
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

func mkSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pgproxy"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}

// bufferedConn wraps a connection with a buffer for data already read
type bufferedConn struct {
	net.Conn
	buf     []byte
	bufRead int
}

func (bc *bufferedConn) Read(p []byte) (n int, err error) {
	// First, drain the buffer
	if bc.bufRead < len(bc.buf) {
		n = copy(p, bc.buf[bc.bufRead:])
		bc.bufRead += n
		return n, nil
	}
	// Buffer drained, read from underlying connection
	return bc.Conn.Read(p)
}
