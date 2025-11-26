package internal

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
)

const (
	tlsHandshakeRecordType = 0x16

	mongoHeaderSize        = 16
	mongoDefaultDatabase   = "admin"
	mongoUsernameMaxLength = 128
)

type mongoConnection struct {
	conn net.Conn
}

func newMongoConnection(conn net.Conn) *mongoConnection {
	return &mongoConnection{conn: conn}
}

func (mc *mongoConnection) Handshake(_ context.Context, database string, clientParams map[string]string) error {
	isMasterDoc := bson.D{
		{Key: "isMaster", Value: 1},
		{Key: "$db", Value: database},
	}

	if appName, ok := clientParams["appName"]; ok && appName != "" {
		isMasterDoc = append(isMasterDoc, bson.E{
			Key: "client",
			Value: bson.D{
				{Key: "application", Value: bson.D{
					{Key: "name", Value: appName},
				}},
			},
		})
	}

	if compression, ok := clientParams["compression"]; ok && compression != "" {
		compressors := strings.Split(compression, ",")
		var compArray bson.A
		for _, c := range compressors {
			compArray = append(compArray, c)
		}
		isMasterDoc = append(isMasterDoc, bson.E{Key: "compression", Value: compArray})
	}

	if err := mc.sendMessage(isMasterDoc); err != nil {
		return fmt.Errorf("failed to send isMaster: %w", err)
	}

	if _, _, err := mc.receiveMessage(); err != nil {
		return fmt.Errorf("failed to receive isMaster response: %w", err)
	}

	return nil
}

func (mc *mongoConnection) AuthenticateSCRAM(_ context.Context, username, password, database string) error {
	scramConv, err := NewSCRAMConversation(username, password)
	if err != nil {
		return err
	}

	clientFirst, err := scramConv.ClientFirst()
	if err != nil {
		return err
	}

	if err := mc.sendMessage(bson.D{
		{Key: "saslStart", Value: 1},
		{Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: primitive.Binary{Data: []byte(clientFirst)}},
		{Key: "$db", Value: database},
	}); err != nil {
		return fmt.Errorf("failed to send SASL start: %w", err)
	}

	saslStartResp, _, err := mc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive SASL start response: %w", err)
	}

	var serverFirst []byte
	var saslStartOk bool
	for _, elem := range saslStartResp {
		if elem.Key == "payload" {
			if val, ok := elem.Value.(primitive.Binary); ok {
				serverFirst = val.Data
			} else {
				return fmt.Errorf("SASL start response payload has invalid type %T, expected Binary", elem.Value)
			}
		} else if elem.Key == "ok" {
			if val, ok := elem.Value.(float64); ok {
				saslStartOk = val == 1.0
			} else {
				return fmt.Errorf("SASL start response ok field has invalid type %T, expected float64", elem.Value)
			}
		}
	}
	if !saslStartOk {
		return fmt.Errorf("SASL start failed: response=%+v", saslStartResp)
	}

	clientFinal, err := scramConv.ClientFinal(string(serverFirst))
	if err != nil {
		return err
	}

	if err := mc.sendMessage(bson.D{
		{Key: "saslContinue", Value: 1},
		{Key: "conversationId", Value: int32(1)},
		{Key: "payload", Value: primitive.Binary{Data: []byte(clientFinal)}},
		{Key: "$db", Value: database},
	}); err != nil {
		return fmt.Errorf("failed to send SASL continue: %w", err)
	}

	saslContinueResp, _, err := mc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive SASL continue response: %w", err)
	}

	var serverFinal []byte
	for _, elem := range saslContinueResp {
		if elem.Key == "payload" {
			if val, ok := elem.Value.(primitive.Binary); ok {
				serverFinal = val.Data
			} else {
				return fmt.Errorf("SASL continue response payload has invalid type %T, expected Binary", elem.Value)
			}
			break
		}
	}

	return scramConv.VerifyServerFinal(string(serverFinal))
}

func (mc *mongoConnection) Underlying() net.Conn {
	return mc.conn
}

func (mc *mongoConnection) sendMessage(doc bson.D) error {
	return SendMongoMessage(mc.conn, doc, 0)
}

func (mc *mongoConnection) receiveMessage() (bson.D, int32, error) {
	return ReceiveMongoMessage(mc.conn)
}

func SendMongoMessage(conn net.Conn, doc bson.D, reqID int32) error {
	docBytes, err := bson.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	var msg []byte
	idx, msg := wiremessage.AppendHeaderStart(msg, reqID, 0, wiremessage.OpMsg)
	msg = wiremessage.AppendMsgFlags(msg, 0)
	msg = wiremessage.AppendMsgSectionType(msg, wiremessage.SingleDocument)
	msg = append(msg, docBytes...)
	msg = bsoncore.UpdateLength(msg, idx, int32(len(msg)))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func ReceiveMongoMessage(conn net.Conn) (bson.D, int32, error) {
	header := make([]byte, mongoHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, 0, fmt.Errorf("reading header: %w", err)
	}

	length, requestID, _, opCode, _, ok := wiremessage.ReadHeader(header)
	if !ok {
		return nil, 0, fmt.Errorf("failed to parse message header")
	}

	body := make([]byte, length-mongoHeaderSize)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, 0, fmt.Errorf("reading body: %w", err)
	}

	var bsonDoc bsoncore.Document
	switch opCode {
	case wiremessage.OpQuery: // OpQuery is deprecated but tools like 'monggosh' still use it as of v2.5.9
		_, remainder, ok := wiremessage.ReadQueryFlags(body)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_QUERY flags")
		}
		_, remainder, ok = wiremessage.ReadQueryFullCollectionName(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_QUERY collection name")
		}
		_, remainder, ok = wiremessage.ReadQueryNumberToSkip(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_QUERY skip count")
		}
		_, remainder, ok = wiremessage.ReadQueryNumberToReturn(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_QUERY return count")
		}
		bsonDoc, _, ok = wiremessage.ReadQueryQuery(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_QUERY query document")
		}

	case wiremessage.OpMsg:
		_, remainder, ok := wiremessage.ReadMsgFlags(body)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_MSG flags")
		}
		_, remainder, ok = wiremessage.ReadMsgSectionType(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_MSG section type")
		}
		bsonDoc, _, ok = wiremessage.ReadMsgSectionSingleDocument(remainder)
		if !ok {
			return nil, 0, fmt.Errorf("failed to read OP_MSG document")
		}

	default:
		return nil, 0, fmt.Errorf("unsupported MongoDB opcode %d", opCode)
	}

	var doc bson.D
	if err := bson.Unmarshal(bsonDoc, &doc); err != nil {
		return nil, 0, fmt.Errorf("unmarshaling document: %w", err)
	}

	return doc, requestID, nil
}
