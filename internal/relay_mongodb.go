package internal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
	"golang.org/x/crypto/pbkdf2"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*mongoRelay)(nil)
var _ protocolHandler = (*mongoRelay)(nil)

type mongoRelay struct {
	relay

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

	if err = r.initSecretsEngine(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *mongoRelay) Serve(tsListener net.Listener) error {
	return serve(&r.relay, r, tsListener)
}

func (r *mongoRelay) initSecretsEngine() error {
	secretsEngine, err := New()
	if err != nil {
		return fmt.Errorf("failed to create MongoDB secrets engine: %v", err)
	}

	// TODO(max) make the ssl mode configurable or detect the stricter mode we can use if we have a cert on hand
	connectionURL := fmt.Sprintf("mongodb://%s:%s@%s:%d/?tls=true",
		r.dbAdminUser, r.dbAdminPass, r.dbHost, r.dbPort)

	_, err = secretsEngine.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connectionURL,
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
	peekBuf := make([]byte, 1)
	if _, err := io.ReadFull(tsConn, peekBuf); err != nil {
		return nil, fmt.Errorf("peeking first byte: %w", err)
	}

	var conn net.Conn
	if peekBuf[0] == 0x16 {
		bufferedConn := NewBufferedConn(tsConn, peekBuf)
		tlsConn := tls.Server(bufferedConn, &tls.Config{
			ServerName:   r.dbHost,
			Certificates: r.relayCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	} else {
		conn = NewBufferedConn(tsConn, peekBuf)
	}

	for {
		header := make([]byte, 16)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, fmt.Errorf("reading message header: %w", err)
		}

		messageLength := int32(binary.LittleEndian.Uint32(header[0:4]))
		opCode := wiremessage.OpCode(binary.LittleEndian.Uint32(header[12:16]))

		bodyLength := messageLength - 16
		body := make([]byte, bodyLength)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, fmt.Errorf("reading message body: %w", err)
		}

		var doc bson.D
		var requestID int32
		var err error

		if opCode == 2004 {
			doc, err = r.parseOpQuery(body)
			if err != nil {
				return nil, fmt.Errorf("parsing OP_QUERY: %w", err)
			}
			requestID = int32(binary.LittleEndian.Uint32(header[4:8]))
		} else if opCode == wiremessage.OpMsg {
			if len(body) < 5 {
				return nil, fmt.Errorf("OP_MSG body too short: %d bytes", len(body))
			}
			if err := bson.Unmarshal(body[5:], &doc); err != nil {
				return nil, fmt.Errorf("unmarshaling OP_MSG: %w", err)
			}
			requestID = int32(binary.LittleEndian.Uint32(header[4:8]))
		} else {
			return nil, fmt.Errorf("unsupported MongoDB opcode %d during handshake", opCode)
		}

		isHandshakeMessage := false
		for _, elem := range doc {
			if elem.Key == "isMaster" || elem.Key == "ismaster" || elem.Key == "hello" {
				isHandshakeMessage = true
				break
			}
		}

		if !isHandshakeMessage {
			return NewBufferedConn(conn, header, body), nil
		}

		builder := bsoncore.NewDocumentBuilder().
			AppendBoolean("ismaster", true).
			AppendBoolean("helloOk", true).
			AppendInt32("maxBsonObjectSize", 16777216).
			AppendInt32("maxMessageSizeBytes", 48000000).
			AppendInt32("maxWriteBatchSize", 100000).
			AppendInt32("minWireVersion", 0).
			AppendInt32("maxWireVersion", 21)

		for _, elem := range doc {
			if elem.Key == "saslSupportedMechs" {
				mechsArray := bsoncore.NewArrayBuilder().
					AppendString("SCRAM-SHA-256").
					AppendString("SCRAM-SHA-1").
					Build()
				builder = builder.AppendArray("saslSupportedMechs", mechsArray)
				break
			}
		}
		responseDoc := builder.AppendDouble("ok", 1.0).Build()

		var responseMsg []byte
		idx, responseMsg := wiremessage.AppendHeaderStart(responseMsg, 0, requestID, wiremessage.OpMsg)
		responseMsg = wiremessage.AppendMsgFlags(responseMsg, 0)
		responseMsg = wiremessage.AppendMsgSectionType(responseMsg, wiremessage.SingleDocument)
		responseMsg = append(responseMsg, responseDoc...)
		responseMsg = bsoncore.UpdateLength(responseMsg, idx, int32(len(responseMsg)))

		if _, err := conn.Write(responseMsg); err != nil {
			return nil, fmt.Errorf("sending OP_MSG handshake response: %w", err)
		}
	}
}

func (r *mongoRelay) parseHandshake(conn net.Conn) (string, string, map[string]string, error) {
	for {
		header := make([]byte, 16)
		if _, err := io.ReadFull(conn, header); err != nil {
			return "", "", nil, fmt.Errorf("reading message header: %w", err)
		}

		messageLength := int32(binary.LittleEndian.Uint32(header[0:4]))
		opCode := int32(binary.LittleEndian.Uint32(header[12:16]))

		if opCode != 2013 {
			return "", "", nil, fmt.Errorf("expected OP_MSG (2013), got %d", opCode)
		}

		bodyLength := messageLength - 16
		body := make([]byte, bodyLength)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", "", nil, fmt.Errorf("reading message body: %w", err)
		}

		if len(body) < 5 {
			return "", "", nil, fmt.Errorf("OP_MSG body too short: %d bytes", len(body))
		}

		var doc bson.D
		if err := bson.Unmarshal(body[5:], &doc); err != nil {
			return "", "", nil, fmt.Errorf("unmarshaling message: %w", err)
		}

		var saslStart bool
		var mechanism string
		var payload []byte
		var database string

		for _, elem := range doc {
			switch elem.Key {
			case "saslStart":
				saslStart = elem.Value.(int32) == 1
			case "mechanism":
				mechanism = elem.Value.(string)
			case "payload":
				payload = elem.Value.(primitive.Binary).Data
			case "$db":
				database = elem.Value.(string)
			}
		}

		if saslStart && (mechanism == "SCRAM-SHA-1" || mechanism == "SCRAM-SHA-256") {
			r.clientSASLPayload = payload
			username, err := r.extractUsernameFromSASL(payload)
			if err != nil {
				return "", "", nil, fmt.Errorf("extracting username from SASL: %w", err)
			}
			if database == "" {
				database = "admin"
			}

			return username, database, make(map[string]string), nil
		}
	}
}

func (r *mongoRelay) createSessionUser(ctx context.Context) error {
	generatedPassword, err := GenerateSecurePassword()
	if err != nil {
		r.relay.metrics.errors.Add("password-generation-failed", 1)
		return err
	}

	creationStatements := dbplugin.Statements{
		Commands: []string{fmt.Sprintf("%s@%s", r.targetRole, r.sessionDatabase)},
	}

	usernameConfig := dbplugin.UsernameMetadata{
		DisplayName: r.targetRole,
		RoleName:    r.targetRole,
	}

	expiration := time.Now().Add(24 * time.Hour)
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

func (r *mongoRelay) deleteSessionUser(ctx context.Context) {
	if r.sessionRole == "" {
		return
	}

	deleteReq := dbplugin.DeleteUserRequest{
		Username: r.sessionRole,
	}

	_, err := r.secretsEngine.DeleteUser(ctx, deleteReq)
	if err != nil {
		r.relay.metrics.errors.Add("revoke-credentials-failed", 1)
	}
}

func (r *mongoRelay) connectToDatabase(ctx context.Context, params map[string]string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = 10 * time.Second
	dbConn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", r.dbHost, r.dbPort))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	tlsConn := tls.Client(dbConn, &tls.Config{
		ServerName: r.dbHost,
		RootCAs:    r.dbCertPool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	if err := r.authenticateToDatabase(ctx, tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("authentication: %w", err)
	}

	return tlsConn, nil
}

func (r *mongoRelay) sendAuthSuccessToClient(conn net.Conn) error {
	scramServer, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		clientPassword := username
		salt := []byte(fmt.Sprintf("%s-salt", username))
		iterations := 4096

		saltedPassword := pbkdf2.Key([]byte(clientPassword), salt, iterations, 32, sha256.New)

		clientKeyHmac := hmac.New(sha256.New, saltedPassword)
		clientKeyHmac.Write([]byte("Client Key"))
		clientKey := clientKeyHmac.Sum(nil)

		storedKeyHash := sha256.Sum256(clientKey)

		serverKeyHmac := hmac.New(sha256.New, saltedPassword)
		serverKeyHmac.Write([]byte("Server Key"))
		serverKey := serverKeyHmac.Sum(nil)

		return scram.StoredCredentials{
			KeyFactors: scram.KeyFactors{
				Salt:  string(salt),
				Iters: iterations,
			},
			StoredKey: storedKeyHash[:],
			ServerKey: serverKey,
		}, nil
	})
	if err != nil {
		return fmt.Errorf("creating SCRAM server: %w", err)
	}

	conv := scramServer.NewConversation()
	serverFirst, err := conv.Step(string(r.clientSASLPayload))
	if err != nil {
		return fmt.Errorf("SCRAM step 1: %w", err)
	}

	step1Doc := bsoncore.NewDocumentBuilder().
		AppendInt32("conversationId", 1).
		AppendBoolean("done", false).
		AppendBinary("payload", 0, []byte(serverFirst)).
		AppendDouble("ok", 1.0).
		Build()

	var step1Msg []byte
	idx, step1Msg := wiremessage.AppendHeaderStart(step1Msg, 0, 0, wiremessage.OpMsg)
	step1Msg = wiremessage.AppendMsgFlags(step1Msg, 0)
	step1Msg = wiremessage.AppendMsgSectionType(step1Msg, wiremessage.SingleDocument)
	step1Msg = append(step1Msg, step1Doc...)
	step1Msg = bsoncore.UpdateLength(step1Msg, idx, int32(len(step1Msg)))

	if _, err := conn.Write(step1Msg); err != nil {
		return fmt.Errorf("writing SASL challenge: %w", err)
	}

	clientFinalDoc, err := r.receiveMongoMessage(conn)
	if err != nil {
		return fmt.Errorf("reading saslContinue: %w", err)
	}

	var clientFinalPayload []byte
	for _, elem := range clientFinalDoc {
		if elem.Key == "payload" {
			clientFinalPayload = elem.Value.(primitive.Binary).Data
			break
		}
	}

	serverFinal, err := conv.Step(string(clientFinalPayload))
	if err != nil {
		return fmt.Errorf("SCRAM step 2: %w", err)
	}

	step2Doc := bsoncore.NewDocumentBuilder().
		AppendInt32("conversationId", 1).
		AppendBoolean("done", true).
		AppendBinary("payload", 0, []byte(serverFinal)).
		AppendDouble("ok", 1.0).
		Build()

	var step2Msg []byte
	idx2, step2Msg := wiremessage.AppendHeaderStart(step2Msg, 0, 0, wiremessage.OpMsg)
	step2Msg = wiremessage.AppendMsgFlags(step2Msg, 0)
	step2Msg = wiremessage.AppendMsgSectionType(step2Msg, wiremessage.SingleDocument)
	step2Msg = append(step2Msg, step2Doc...)
	step2Msg = bsoncore.UpdateLength(step2Msg, idx2, int32(len(step2Msg)))

	if _, err := conn.Write(step2Msg); err != nil {
		return fmt.Errorf("writing SASL success: %w", err)
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
	buf := make([]byte, 32768)
	for {
		n, err := clientConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading from client: %w", err)
		}

		if auditFile != nil {
			r.auditMessage(auditFile, buf[:n], "client->db")
		}

		if _, err := dbConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("writing to database: %w", err)
		}
	}
}

func (r *mongoRelay) proxyDatabaseToClient(dbConn, clientConn net.Conn) error {
	buf := make([]byte, 32768)
	for {
		n, err := dbConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading from database: %w", err)
		}

		if _, err := clientConn.Write(buf[:n]); err != nil {
			return fmt.Errorf("writing to client: %w", err)
		}
	}
}

func (r *mongoRelay) auditMessage(auditFile *os.File, data []byte, direction string) {
	if len(data) < 16 {
		return
	}

	opCode := int32(binary.LittleEndian.Uint32(data[12:16]))
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	if opCode == 2013 && len(data) > 17 {
		var doc bson.D
		if err := bson.Unmarshal(data[17:], &doc); err == nil {
			for _, elem := range doc {
				if elem.Key == "find" || elem.Key == "insert" || elem.Key == "update" || elem.Key == "delete" {
					fmt.Fprintf(auditFile, "[%s] %s %s: %v\n", timestamp, direction, elem.Key, elem.Value)
					return
				}
			}
		}
	}

	fmt.Fprintf(auditFile, "[%s] %s opCode=%d len=%d\n", timestamp, direction, opCode, len(data))
}

func (r *mongoRelay) sendMongoMessage(conn net.Conn, doc bson.D) error {
	docBytes, err := bson.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshaling document: %w", err)
	}

	var msg []byte
	idx, msg := wiremessage.AppendHeaderStart(msg, 0, 0, wiremessage.OpMsg)
	msg = wiremessage.AppendMsgFlags(msg, 0)
	msg = wiremessage.AppendMsgSectionType(msg, wiremessage.SingleDocument)
	msg = append(msg, docBytes...)
	msg = bsoncore.UpdateLength(msg, idx, int32(len(msg)))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}

func (r *mongoRelay) receiveMongoMessage(conn net.Conn) (bson.D, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	messageLength := int32(binary.LittleEndian.Uint32(header[0:4]))
	bodyLength := messageLength - 16

	if bodyLength < 5 {
		return nil, fmt.Errorf("message body too short: %d bytes", bodyLength)
	}

	body := make([]byte, bodyLength)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	var doc bson.D
	if err := bson.Unmarshal(body[5:], &doc); err != nil {
		return nil, fmt.Errorf("unmarshaling document: %w", err)
	}

	return doc, nil
}

func (r *mongoRelay) parseOpQuery(body []byte) (bson.D, error) {
	if len(body) < 12 {
		return nil, fmt.Errorf("OP_QUERY body too short: %d bytes", len(body))
	}

	offset := 4

	for offset < len(body) && body[offset] != 0 {
		offset++
	}
	if offset >= len(body) {
		return nil, fmt.Errorf("collection name not null-terminated")
	}
	offset++

	if offset+8 > len(body) {
		return nil, fmt.Errorf("OP_QUERY missing skip/return fields")
	}
	offset += 8

	var doc bson.D
	if err := bson.Unmarshal(body[offset:], &doc); err != nil {
		return nil, fmt.Errorf("unmarshaling query document: %w", err)
	}

	return doc, nil
}

func (r *mongoRelay) extractUsernameFromSASL(payload []byte) (string, error) {
	clientFirst := string(payload)

	start := 0
	for i := 0; i < len(clientFirst); i++ {
		if clientFirst[i] == 'n' && i+1 < len(clientFirst) && clientFirst[i+1] == '=' {
			start = i + 2
			break
		}
	}

	if start == 0 {
		return "", fmt.Errorf("username not found in SASL payload")
	}

	end := start
	for i := start; i < len(clientFirst); i++ {
		if clientFirst[i] == ',' {
			end = i
			break
		}
	}

	if end == start {
		end = len(clientFirst)
	}

	return clientFirst[start:end], nil
}

func (r *mongoRelay) authenticateToDatabase(ctx context.Context, conn net.Conn) error {
	isMasterDoc := bson.D{
		{Key: "isMaster", Value: 1},
		{Key: "$db", Value: r.sessionDatabase},
	}

	if err := r.sendMongoMessage(conn, isMasterDoc); err != nil {
		return fmt.Errorf("sending isMaster: %w", err)
	}

	if _, err := r.receiveMongoMessage(conn); err != nil {
		return fmt.Errorf("receiving isMaster response: %w", err)
	}

	actualUsername := r.sessionRole
	if idx := strings.Index(r.sessionRole, "@"); idx != -1 {
		actualUsername = r.sessionRole[:idx]
	}

	scram, err := NewSCRAMConversation(actualUsername, r.sessionPassword)
	if err != nil {
		return err
	}

	clientFirst, err := scram.ClientFirst()
	if err != nil {
		return err
	}

	saslStartDoc := bson.D{
		{Key: "saslStart", Value: 1},
		{Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: primitive.Binary{Data: []byte(clientFirst)}},
		{Key: "$db", Value: r.sessionDatabase},
	}

	if err := r.sendMongoMessage(conn, saslStartDoc); err != nil {
		return fmt.Errorf("sending SASL start: %w", err)
	}

	saslStartResp, err := r.receiveMongoMessage(conn)
	if err != nil {
		return fmt.Errorf("receiving SASL start response: %w", err)
	}

	var serverFirst []byte
	var ok float64
	for _, elem := range saslStartResp {
		if elem.Key == "payload" {
			serverFirst = elem.Value.(primitive.Binary).Data
		} else if elem.Key == "ok" {
			ok = elem.Value.(float64)
		}
	}

	if ok != 1.0 {
		return fmt.Errorf("SASL start failed: response=%+v", saslStartResp)
	}

	if len(serverFirst) == 0 {
		return fmt.Errorf("SASL start response missing payload: %+v", saslStartResp)
	}

	clientFinal, err := scram.ClientFinal(string(serverFirst))
	if err != nil {
		return err
	}

	saslContinueDoc := bson.D{
		{Key: "saslContinue", Value: 1},
		{Key: "conversationId", Value: int32(1)},
		{Key: "payload", Value: primitive.Binary{Data: []byte(clientFinal)}},
		{Key: "$db", Value: r.sessionDatabase},
	}

	if err := r.sendMongoMessage(conn, saslContinueDoc); err != nil {
		return fmt.Errorf("sending SASL continue: %w", err)
	}

	saslContinueResp, err := r.receiveMongoMessage(conn)
	if err != nil {
		return fmt.Errorf("receiving SASL continue response: %w", err)
	}

	var serverFinal []byte
	for _, elem := range saslContinueResp {
		if elem.Key == "payload" {
			serverFinal = elem.Value.(primitive.Binary).Data
			break
		}
	}

	return scram.VerifyServerFinal(string(serverFinal))
}
