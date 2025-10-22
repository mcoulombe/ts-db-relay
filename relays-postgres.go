package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openbao/openbao/plugins/database/postgresql"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var (
	sslStart       = [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	plaintextStart = [8]byte{0, 0, 0, 86, 0, 3, 0, 0}
)

var _ Relay = (*postgresRelay)(nil)

type postgresRelay struct {
	base

	dbAddr         string
	dbHost         string
	dbPort         string
	dbAdminUser    string
	dbAdminPass    string
	dbCertPool     *x509.CertPool
	downstreamCert []tls.Certificate

	sessionDatabase string
	sessionUser     string
	sessionPassword string
}

func newPostgresRelay(dbAddr, dbCAPath, dbAdminUser, dbAdminPass string, tsClient *local.Client) (*postgresRelay, error) {
	dbHost, dbPort, err := net.SplitHostPort(dbAddr)
	if err != nil {
		return nil, err
	}

	dbCA, err := os.ReadFile(dbCAPath)
	if err != nil {
		return nil, err
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCAPath)
	}
	downstreamCert, err := mkSelfSigned(dbHost)
	if err != nil {
		return nil, err
	}

	r := &postgresRelay{
		dbAddr:         dbAddr,
		dbHost:         dbHost,
		dbPort:         dbPort,
		dbAdminUser:    dbAdminUser,
		dbAdminPass:    dbAdminPass,
		dbCertPool:     dbCertPool,
		downstreamCert: []tls.Certificate{downstreamCert},
	}

	r.base = base{
		metrics: &relayMetrics{
			errors: metrics.LabelMap{Label: "kind"},
		},
		tsClient: tsClient,
		serve:    r.serve,
	}

	if err := r.initPlugin(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *postgresRelay) initPlugin() error {
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

func (r *postgresRelay) serve(tsConn net.Conn) error {
	defer tsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create upstream and downstream connections so the relay can:
	// * impersonate a database user from the Tailscale identity
	// * audit incoming queries
	// * forward traffic between the client and the database
	dbConn, dbClient, err := initDBConnections(r.dbAddr, r.dbHost, r.dbCertPool)
	defer dbConn.Close()
	if err != nil {
		r.base.metrics.errors.Add("database-connection", 1)
		return err
	}

	clientIsTLS, err := interceptStartSSL(tsConn, dbConn)
	if err != nil {
		r.base.metrics.errors.Add("client-protocol", 1)
		return err
	}

	err = performTLSHandshake(ctx, dbClient, tsConn, dbConn, clientIsTLS)
	if err != nil {
		r.base.metrics.errors.Add("tls-handshake", 1)
		return err
	}

	clientConn, err := initClientConnection(ctx, r.dbHost, r.downstreamCert, tsConn, clientIsTLS)
	if err != nil {
		r.base.metrics.errors.Add("client-connection", 1)
		return err
	}

	// Bidirectional connection is established, impersonate the desired database user, if allowed
	params, err := interceptStartupMessage(clientConn)
	if err != nil {
		r.base.metrics.errors.Add("start-up-message", 1)
		return err
	}
	r.sessionUser = params["user"]
	r.sessionDatabase = params["database"]

	// Verify access based on Tailscale identity and capabilities
	user, machine, capabilities, err := r.getClientIdentity(ctx, tsConn)
	if err != nil {
		r.base.metrics.errors.Add("authentication", 1)
		return err
	}

	allowed, err := r.hasAccess(user, machine, "postgres", r.sessionDatabase, r.sessionUser, capabilities)
	if err != nil {
		r.base.metrics.errors.Add("authentication", 1)
		return err
	}
	if !allowed {
		r.base.metrics.errors.Add("authorization", 1)
		return err
	}

	// Tailnet user is allowed, generate & authenticate via an ephemeral user for the session
	err = r.seedCredentials(ctx)
	if err != nil {
		r.base.metrics.errors.Add("seed-credentials", 1)
		return err
	}

	if err := writeHijackedStartupToDatabase(dbClient, r.sessionUser, r.sessionDatabase); err != nil {
		r.base.metrics.errors.Add("start-up-params", 1)
		return fmt.Errorf("sending startup to upstream: %v", err)
	}

	if err := interceptAuthAndInjectPassword(dbClient, clientConn, r.sessionUser, r.sessionPassword); err != nil {
		r.base.metrics.errors.Add("inject-credentials", 1)
		return err
	}
	if err := forwardInitialServerMessages(dbClient, clientConn); err != nil {
		r.base.metrics.errors.Add("wait-for-readiness", 1)
		return err
	}

	// Create audit file for this session
	auditFile, err := createAuditFile(user, machine, "postgres", r.dbHost, r.sessionDatabase, r.sessionUser)
	if err != nil {
		r.base.metrics.errors.Add("audit-file-create-failed", 1)
		return fmt.Errorf("failed to create audit file: %v", err)
	}
	defer auditFile.Close()

	// Impersonation all set, just relay the traffic as long as the connection is alive
	r.base.metrics.startedSessions.Add(1)
	r.base.metrics.activeSessions.Add(1)
	defer r.base.metrics.activeSessions.Add(-1)

	entryFinished := make(chan struct{}, 10)
	errc := make(chan error, 1)
	go func() {
		_, err := auditCopy(auditFile, dbClient, clientConn, entryFinished)
		errc <- err
	}()
	go func() {
		_, err := copyAndDetectEntryFinished(clientConn, dbClient, entryFinished)
		errc <- err
	}()
	if err := <-errc; err != nil {
		return fmt.Errorf("session terminated with error: %v", err)
	}
	return nil
}

func (r *postgresRelay) seedCredentials(ctx context.Context) error {
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		r.base.metrics.errors.Add("password-generation-failed", 1)
		return fmt.Errorf("failed to generate random password: %v", err)
	}
	generatedPassword := hex.EncodeToString(passwordBytes)

	creationStatements := dbplugin.Statements{
		Commands: []string{
			fmt.Sprintf(`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`),
			fmt.Sprintf(`GRANT "%s" TO "{{name}}";`, r.sessionUser),
		},
	}

	usernameConfig := dbplugin.UsernameMetadata{
		DisplayName: r.sessionUser,
		RoleName:    r.sessionUser,
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
		return fmt.Errorf("failed to generate credentials for user %s: %v", r.sessionUser, err)
	}

	r.sessionUser = resp.Username
	r.sessionPassword = generatedPassword

	return nil
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

func initDBConnections(dbAddr, dbHost string, dbCertPool *x509.CertPool) (net.Conn, *tls.Conn, error) {
	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.Dial("tcp", dbAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream dial: %v", err)
	}

	dbClient := tls.Client(dbConn, &tls.Config{
		ServerName: dbHost,
		RootCAs:    dbCertPool,
		MinVersion: tls.VersionTLS12,
	})

	return dbConn, dbClient, nil
}

func initClientConnection(ctx context.Context, dbHost string, certs []tls.Certificate, tsConn net.Conn, clientIsTLS bool) (net.Conn, error) {
	var clientConn net.Conn

	if clientIsTLS {
		tlsConn := tls.Server(tsConn, &tls.Config{
			ServerName:   dbHost,
			Certificates: certs,
			MinVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("client TLS handshake: %v", err)
		}
		clientConn = tlsConn
	} else {
		if _, err := tsConn.Write(plaintextStart[:]); err != nil {
			return nil, fmt.Errorf("sending initial client bytes to upstream: %v", err)
		}
		clientConn = tsConn
	}

	return clientConn, nil
}

func interceptStartSSL(clientConn net.Conn, dbConn net.Conn) (bool, error) {
	var buf [8]byte
	if _, err := io.ReadFull(clientConn, buf[:8]); err != nil {
		return false, fmt.Errorf("failed to verify if client is using TLS, initial magic read: %v", err)
	}

	if _, err := dbConn.Write(buf[:]); err != nil {
		return false, fmt.Errorf("failed to verify if client is using TLS, upstream write of start-ssl magic: %v", err)
	}

	return buf == sslStart, nil
}

func performTLSHandshake(ctx context.Context, dbTLSClient *tls.Conn, tsConn, dbConn net.Conn, clientIsTLS bool) error {
	var buf [1]byte
	if _, err := io.ReadFull(dbConn, buf[:1]); err != nil {
		return fmt.Errorf("error reading database start-ssl response: %v", err)
	}
	if buf[0] != 'S' {
		return fmt.Errorf("database didn't acknowledge start-ssl, said %q", buf[0])
	}

	if err := dbTLSClient.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("failed database TLS handshake: %v", err)
	}

	if clientIsTLS {
		if _, err := io.WriteString(tsConn, "S"); err != nil {
			return fmt.Errorf("error writing start-ssl ack to client: %v", err)
		}
	}

	return nil
}

func interceptStartupMessage(clientConn net.Conn) (map[string]string, error) {
	var buf [4]byte
	if _, err := io.ReadFull(clientConn, buf[:]); err != nil {
		return nil, err
	}

	length := int(binary.BigEndian.Uint32(buf[:]))
	if length < 8 {
		return nil, fmt.Errorf("invalid startup length %d", length)
	}

	buf2 := make([]byte, length-4)
	if _, err := io.ReadFull(clientConn, buf2[:]); err != nil {
		return nil, err
	}

	startup := append(buf[:], buf2[:]...)

	if len(startup) < 8 {
		return nil, fmt.Errorf("startup too short")
	}

	kv := startup[8:]
	parts := bytes.Split(kv, []byte{0})
	params := make(map[string]string)
	for i := 0; i+1 < len(parts); i += 2 {
		k := string(parts[i])
		if k == "" {
			break
		}
		params[k] = string(parts[i+1])
	}

	return params, nil
}

func forwardInitialServerMessages(dbConn, clientConn net.Conn) error {
	for {
		mt, mb, err := readMessage(dbConn)
		if err != nil {
			return err
		}

		if err := writeMessage(clientConn, mt, mb); err != nil {
			return err
		}
		if mt == 'Z' { // ReadyForQuery
			return nil
		}
	}
}

func writeHijackedStartupToDatabase(dbConn net.Conn, user, database string) error {
	// protocol version 3.0
	buf := new(bytes.Buffer)
	// placeholder for length
	binary.Write(buf, binary.BigEndian, int32(0))
	// protocol number
	binary.Write(buf, binary.BigEndian, int32(196608)) // 3.0
	// parameters: user\0 database\0 application_name\0\0
	buf.WriteString("user")
	buf.WriteByte(0)
	buf.WriteString(user)
	buf.WriteByte(0)
	if database != "" {
		buf.WriteString("database")
		buf.WriteByte(0)
		buf.WriteString(database)
		buf.WriteByte(0)
	}
	buf.WriteByte(0) // terminator
	// set length
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b[0:4], uint32(len(b)))

	_, err := dbConn.Write(b)
	return err
}

// readMessage reads a normal typed PostgreSQL message from r.
// Returns (type byte, payload []byte) where payload == full body (length-4 bytes).
func readMessage(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	length := int(binary.BigEndian.Uint32(hdr[1:5]))
	if length < 4 {
		return 0, nil, fmt.Errorf("invalid message length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return msgType, body, nil
}

// writeMessage writes a typed message to w (type byte + int32 length + body).
func writeMessage(w io.Writer, msgType byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = msgType
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)+4))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// buildPasswordBody builds the body for a PasswordMessage (password bytes + \0)
func buildPasswordBody(password string) []byte {
	b := make([]byte, len(password)+1)
	copy(b, password)
	b[len(b)-1] = 0
	return b
}

func interceptAuthAndInjectPassword(dbConn, clientConn net.Conn, sessionUser, sessionPassword string) error {
	// 1) read upstream message (should be 'R')
	msgType, body, err := readMessage(dbConn)
	if err != nil {
		return fmt.Errorf("read upstream auth req: %w", err)
	}
	if msgType != 'R' {
		return fmt.Errorf("expected upstream AuthenticationRequest 'R', got %q", msgType)
	}

	// Parse auth type
	if len(body) < 4 {
		return fmt.Errorf("upstream auth body too short")
	}
	authType := int(binary.BigEndian.Uint32(body[0:4]))

	// ---- DON'T forward the request to client ----
	// Instead, immediately tell the client "auth succeeded".
	authOk := make([]byte, 4)
	binary.BigEndian.PutUint32(authOk, 0) // AuthenticationOk code = 0
	if err := writeMessage(clientConn, 'R', authOk); err != nil {
		return fmt.Errorf("send fake auth ok to client: %w", err)
	}

	// 2) Handle upstream authentication using static password
	switch authType {
	case 3: // cleartext
		if err := writeMessage(dbConn, 'p', buildPasswordBody(sessionPassword)); err != nil {
			return fmt.Errorf("send upstream cleartext pw: %w", err)
		}
	case 5: // md5
		if len(body) < 8 {
			return fmt.Errorf("md5 auth body too short")
		}
		var salt [4]byte
		copy(salt[:], body[4:8])
		resp := md5Response(sessionPassword, sessionUser, salt)
		if err := writeMessage(dbConn, 'p', buildPasswordBody(resp)); err != nil {
			return fmt.Errorf("send upstream md5 pw: %w", err)
		}
	default:
		return fmt.Errorf("unsupported upstream auth type %d", authType)
	}

	// 3) Drain upstream messages until AuthenticationOk
	for {
		mt, mb, err := readMessage(dbConn)
		if err != nil {
			return fmt.Errorf("read upstream post-auth: %w", err)
		}
		if mt == 'R' {
			if len(mb) >= 4 && int(binary.BigEndian.Uint32(mb[:4])) == 0 {
				// Upstream auth ok. We already told client it’s ok, so just ignore.
				break
			}
			return fmt.Errorf("unexpected extra auth step from upstream")
		}
		if mt == 'E' {
			// If upstream rejected, forward error to client
			_ = writeMessage(clientConn, mt, mb)
			return fmt.Errorf("upstream auth error")
		}
		// Forward any other startup messages (ParameterStatus, etc.)
		if err := writeMessage(clientConn, mt, mb); err != nil {
			return fmt.Errorf("forward upstream msg: %w", err)
		}
	}

	return nil
}

// md5Response computes the md5 response string for Postgres md5 auth:
// result = "md5" + hex(md5( hex(md5(password+username)) + salt ))
func md5Response(password, username string, salt [4]byte) string {
	h1 := md5.Sum([]byte(password + username))
	h1hex := hex.EncodeToString(h1[:])
	h2inp := append([]byte(h1hex), salt[:]...)
	h2 := md5.Sum(h2inp)
	return "md5" + hex.EncodeToString(h2[:])
}

func auditCopy(auditFile *os.File, dst io.Writer, src io.Reader, entryFinished <-chan struct{}) (int64, error) {
	var written int64
	var auditBuffer bytes.Buffer
	readBuf := make([]byte, 32*1024)
	queryStartTime := time.Now()

	// Create a channel for read operations
	type readResult struct {
		n   int
		err error
	}
	readChan := make(chan readResult, 1)

	// Start a goroutine to perform blocking reads
	go func() {
		for {
			n, err := src.Read(readBuf)
			readChan <- readResult{n, err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-entryFinished:
			// Flush accumulated buffer when entry is complete
			if auditBuffer.Len() > 0 {
				flushAuditBuffer(auditFile, &auditBuffer, queryStartTime)
				queryStartTime = time.Now() // Reset timer for next entry
			}

		case result := <-readChan:
			if result.n > 0 {
				// Accumulate data in audit buffer
				auditBuffer.Write(readBuf[:result.n])

				// Forward to destination
				nw, ew := dst.Write(readBuf[:result.n])
				if nw < 0 || result.n < nw {
					nw = 0
					if ew == nil {
						ew = fmt.Errorf("invalid write result")
					}
				}
				written += int64(nw)
				if ew != nil {
					return written, ew
				}
				if result.n != nw {
					return written, io.ErrShortWrite
				}
			}
			if result.err != nil {
				// Flush any remaining buffer before exiting
				if auditBuffer.Len() > 0 {
					flushAuditBuffer(auditFile, &auditBuffer, queryStartTime)
				}
				if result.err != io.EOF {
					return written, result.err
				}
				return written, nil
			}
		}
	}
}

// copyAndDetectEntryFinished copies data from src to dst and signals on the channel
// whenever a ReadyForQuery ('Z') message is detected from the PostgreSQL server
func copyAndDetectEntryFinished(dst io.Writer, src io.Reader, entryFinished chan<- struct{}) (int64, error) {
	var written int64
	buf := make([]byte, 32*1024)
	msgBuf := bytes.Buffer{}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Accumulate in message buffer for parsing
			msgBuf.Write(buf[:nr])

			// Check for ReadyForQuery messages in the accumulated buffer
			for msgBuf.Len() >= 5 {
				// PostgreSQL message format: type (1 byte) + length (4 bytes) + body
				msgType := msgBuf.Bytes()[0]
				if msgBuf.Len() < 5 {
					break
				}

				msgLen := int(binary.BigEndian.Uint32(msgBuf.Bytes()[1:5]))
				totalLen := 1 + msgLen

				// Wait for complete message
				if msgBuf.Len() < totalLen {
					break
				}

				// Check if this is a ReadyForQuery message
				if msgType == 'Z' {
					// Signal that the audit entry is complete
					select {
					case entryFinished <- struct{}{}:
					default:
						// Channel full, skip signal
					}
				}

				// Consume the message from buffer
				msgBuf.Next(totalLen)
			}

			// Forward to destination
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

// extractQueryText parses PostgreSQL protocol messages and extracts query text
func extractQueryText(data []byte) string {
	var queries []string
	offset := 0

	for offset < len(data) {
		if offset+5 > len(data) {
			break
		}

		msgType := data[offset]
		msgLen := int(binary.BigEndian.Uint32(data[offset+1 : offset+5]))
		totalLen := 1 + msgLen

		if offset+totalLen > len(data) {
			break
		}

		// 'Q' is the Simple Query message type
		if msgType == 'Q' {
			// Query string starts after type (1 byte) + length (4 bytes)
			// and ends with a null terminator
			queryStart := offset + 5
			queryEnd := offset + totalLen - 1 // Exclude null terminator

			if queryEnd > queryStart && queryEnd <= len(data) {
				query := string(data[queryStart:queryEnd])
				queries = append(queries, query)
			}
		}

		offset += totalLen
	}

	return strings.Join(queries, "; ")
}
