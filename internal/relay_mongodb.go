package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*mongoRelay)(nil)

type mongoRelay struct {
	relay

	// TODO(max) move session data outside the relay so the same instance can serve multiple connections
	clientSASLPayload []byte
}

func newMongo(dbKey string, dbCfg *DBConfig, tsClient *local.Client) (*mongoRelay, error) {
	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}
	relayCert, err := GenerateSelfSignedCert(dbCfg.Host)
	if err != nil {
		return nil, err
	}

	r := &mongoRelay{
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

func (r *mongoRelay) initSecretsEngine() error {
	secretsEngine, err := New()
	if err != nil {
		return fmt.Errorf("failed to create MongoDB secrets engine: %v", err)
	}

	// TODO(max) make the SSL mode configurable or detect the stricter mode we can use if we have a cert on hand
	connectionURL := fmt.Sprintf("mongodb://%s:%s@%s:%d/?tls=true",
		r.dbAdminUser, r.dbAdminPass, r.dbHost, r.dbPort)

	_, err = secretsEngine.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"client_options": options.Client().
				ApplyURI(connectionURL).
				SetTLSConfig(&tls.Config{
					RootCAs:    r.dbCertPool,
					ServerName: r.dbHost,
					MinVersion: tls.VersionTLS12,
				}),
		},
		VerifyConnection: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize MongoDB secrets engine: %v", err)
	}

	r.secretsEngine = secretsEngine
	return nil
}

func (r *mongoRelay) handleTLSNegotiation(ctx context.Context, tsConn net.Conn) (net.Conn, error) {
	// Peek the first byte to determine if the client is initiating a TLS handshake
	buf := make([]byte, 1)
	if _, err := io.ReadFull(tsConn, buf); err != nil {
		return nil, fmt.Errorf("failed to peek the connection data to handle TLS negociation: %w", err)
	}

	if buf[0] == tlsHandshakeRecordType {
		bufferedConn := NewBufferedConn(tsConn, buf)
		tlsConn := tls.Server(bufferedConn, &tls.Config{
			ServerName:   r.dbHost,
			Certificates: r.relayCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return NewBufferedConn(tsConn, buf), nil
}

func (r *mongoRelay) parseHandshake(ctx context.Context, conn net.Conn) (string, string, map[string]string, error) {
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", "", nil, nil
			}
			return "", "", nil, err
		default:
		}

		// Get the next message from the client
		doc, reqID, err := ReceiveMongoMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", "", nil, nil
			}
			return "", "", nil, fmt.Errorf("failed to read message: %w", err)
		}

		// Extract relevant fields from handshake messages
		var saslStart bool
		var payload []byte
		database := mongoDefaultDatabase
		params := map[string]string{}
		isHandshakeMessage := false

		for _, elem := range doc {
			switch elem.Key {
			case "isMaster", "ismaster", "hello":
				isHandshakeMessage = true
			case "saslStart":
				if val, ok := elem.Value.(int32); ok {
					saslStart = val == 1
				} else {
					return "", "", nil, fmt.Errorf("saslStart field has invalid type %T, expected int32", elem.Value)
				}
			case "payload":
				if val, ok := elem.Value.(primitive.Binary); ok {
					payload = val.Data
				} else {
					return "", "", nil, fmt.Errorf("payload field has invalid type %T, expected Binary", elem.Value)
				}
			case "$db":
				if val, ok := elem.Value.(string); ok {
					database = val
				}
			case "compression":
				if val, ok := elem.Value.(bson.A); ok {
					var compressors []string
					for _, c := range val {
						if compressor, ok := c.(string); ok {
							compressors = append(compressors, compressor)
						}
					}
					if len(compressors) > 0 {
						params["compression"] = strings.Join(compressors, ",")
					}
				}
			case "client":
				if clientDoc, ok := elem.Value.(bson.D); ok {
					for _, clientElem := range clientDoc {
						if clientElem.Key == "application" {
							if appDoc, ok := clientElem.Value.(bson.D); ok {
								for _, appElem := range appDoc {
									if appElem.Key == "name" {
										if appName, ok := appElem.Value.(string); ok {
											params["appName"] = appName
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Monitoring connections: MongoDB drivers send periodic handshake messages to check server health.
		// We respond to these indefinitely until the context is canceled, the client closes the connection,
		// or the client responds with a saslStart message.
		if isHandshakeMessage {
			// TODO(max) do a handshake with the underlying database to return the actual server capabilities
			if err := SendMongoMessage(conn, bson.D{
				{"isMaster", true},
				{"helloOk", true},
				{"maxBsonObjectSize", int32(16777216)},
				{"maxMessageSizeBytes", int32(48000000)},
				{"maxWriteBatchSize", int32(100000)},
				{"minWireVersion", int32(0)},
				{"maxWireVersion", int32(21)},
				{"ok", 1.0},
				{"saslSupportedMechs", bson.A{"SCRAM-SHA-256"}},
			}, reqID); err != nil {
				return "", "", nil, fmt.Errorf("failed to send SASL challenge: %w", err)
			}

			continue
		}

		// saslStart means this connection is trying to authenticate, continue with the rest of the relay protocol
		if saslStart {
			r.clientSASLPayload = payload
			username, err := ExtractUsernameFromSASL(payload)
			if err != nil {
				return "", "", nil, fmt.Errorf("extracting username from SASL: %w", err)
			}

			return username, database, params, nil
		}

		return "", "", nil, fmt.Errorf("unexpected message type, expected handshake or saslStart")
	}
}

func (r *mongoRelay) createSessionUser(ctx context.Context) error {
	generatedPassword, err := GenerateSecurePassword()
	if err != nil {
		return err
	}

	generatedUsername, err := GenerateEphemeralUsername(r.targetRole, mongoUsernameMaxLength)
	if err != nil {
		return err
	}

	resp, err := r.secretsEngine.NewUser(ctx, dbplugin.NewUserRequest{
		Password: generatedPassword,
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: generatedUsername,
			RoleName:    r.targetRole,
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(`{"auth_source": %q}`, r.sessionDatabase)},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to generate user to impersonate from %q: %v", r.targetRole, err)
	}

	r.sessionRole = resp.Username
	r.sessionPassword = generatedPassword

	return nil
}

func (r *mongoRelay) deleteSessionUser(ctx context.Context) error {
	if _, err := r.secretsEngine.DeleteUser(ctx, dbplugin.DeleteUserRequest{
		Username: r.sessionRole,
	}); err != nil {
		return err
	}

	return nil
}

func (r *mongoRelay) connectToDatabase(ctx context.Context, params map[string]string) (net.Conn, error) {
	username, _, err := decodeMongoDBUsername(r.sessionRole)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MongoDB username: %w", err)
	}

	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", r.dbHost, r.dbPort))
	if err != nil {
		return nil, fmt.Errorf("failed to dial database: %w", err)
	}

	tlsConn := tls.Client(dbConn, &tls.Config{
		ServerName: r.dbHost,
		RootCAs:    r.dbCertPool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("failed TLS handshake with database: %w", err)
	}

	mongoConn := newMongoConnection(tlsConn)
	if err := mongoConn.Handshake(ctx, r.sessionDatabase, params); err != nil {
		tlsConn.Close()
		return nil, err
	}
	if err := mongoConn.AuthenticateSCRAM(ctx, username, r.sessionPassword, r.sessionDatabase); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return mongoConn.Underlying(), nil
}

func (r *mongoRelay) sendAuthSuccessToClient(conn net.Conn) error {
	scramServer, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		return GenerateSCRAMCredentials(username)
	})
	if err != nil {
		return fmt.Errorf("failed to create SCRAM server: %w", err)
	}

	conv := scramServer.NewConversation()
	serverFirst, err := conv.Step(string(r.clientSASLPayload))
	if err != nil {
		return err
	}

	if err := SendMongoMessage(conn, bson.D{
		{"conversationId", int32(1)},
		{"done", false},
		{"payload", primitive.Binary{Data: []byte(serverFirst)}},
		{"ok", 1.0},
	}, 0); err != nil {
		return fmt.Errorf("failed to send SASL challenge: %w", err)
	}

	clientFinalDoc, _, err := ReceiveMongoMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read saslContinue: %w", err)
	}

	var clientFinalPayload []byte
	for _, elem := range clientFinalDoc {
		if elem.Key == "payload" {
			if val, ok := elem.Value.(primitive.Binary); ok {
				clientFinalPayload = val.Data
			} else {
				return fmt.Errorf("payload field has invalid type %T, expected Binary", elem.Value)
			}
			break
		}
	}

	serverFinal, err := conv.Step(string(clientFinalPayload))
	if err != nil {
		return err
	}

	if err := SendMongoMessage(conn, bson.D{
		{"conversationId", int32(1)},
		{"done", true},
		{"payload", primitive.Binary{Data: []byte(serverFinal)}},
		{"ok", 1.0},
	}, 0); err != nil {
		return fmt.Errorf("failed to send SASL success: %w", err)
	}

	if !conv.Valid() {
		return fmt.Errorf("SCRAM conversation invalid")
	}

	return nil
}

func (r *mongoRelay) proxyConnection(clientConn, dbConn net.Conn, auditFile *os.File) error {
	errc := make(chan error, 2)

	go func() {
		errc <- r.proxyClientToDatabase(clientConn, dbConn, auditFile)
	}()

	go func() {
		errc <- r.proxyDatabaseToClient(dbConn, clientConn)
	}()

	return <-errc
}

func (r *mongoRelay) proxyClientToDatabase(clientConn, dbConn net.Conn, auditFile *os.File) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read from client: %w", err)
		}

		if auditFile != nil {
			auditQuery(auditFile, string(buf[:n]))
		}

		if _, err := dbConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write to database: %w", err)
		}
	}
}

func (r *mongoRelay) proxyDatabaseToClient(dbConn, clientConn net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := dbConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read from database: %w", err)
		}

		if _, err := clientConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write to client: %w", err)
		}
	}
}
