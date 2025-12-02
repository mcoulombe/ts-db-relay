package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoDBPlugin struct {
	client *mongo.Client
}

type mongoDBConfig struct {
	ClientOptions *options.ClientOptions `mapstructure:"client_options"`
}

type mongoDBNewUserStatement struct {
	// The authentication database (also called auth source) where the target user is defined.
	// https://www.mongodb.com/docs/php-library/current/security/authentication/scram/#scram-sha-256
	AuthSource string `json:"auth_source"`
}

type mongoDBUserInfo struct {
	Users []struct {
		Roles []bson.M `bson:"roles"`
	} `bson:"users"`
}

func New() (dbplugin.Database, error) {
	return &mongoDBPlugin{}, nil
}

func (m *mongoDBPlugin) Type() (string, error) {
	return "mongodb", nil
}

func (m *mongoDBPlugin) Close() error {
	if m.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.client.Disconnect(ctx)
	}
	return nil
}

func (m *mongoDBPlugin) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	config := &mongoDBConfig{}
	if err := mapstructure.Decode(req.Config, config); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to decode config: %w", err)
	}

	if config.ClientOptions == nil || config.ClientOptions.GetURI() == "" {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid config, client_options with at least a connection URI is required")
	}

	client, err := mongo.Connect(ctx, config.ClientOptions)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to instantiate database client: %w", err)
	}
	m.client = client

	if req.VerifyConnection {
		if err := m.client.Ping(ctx, nil); err != nil {
			m.client.Disconnect(ctx)
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to ping the database as part of connectivity verification: %w", err)
		}

	}

	return dbplugin.InitializeResponse{
		Config: req.Config,
	}, nil
}

func (m *mongoDBPlugin) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	newUsername := req.UsernameConfig.DisplayName
	if newUsername == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("username is required")
	}

	userToImpersonate := req.UsernameConfig.RoleName
	if userToImpersonate == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("role name (target user to impersonate) is required")
	}

	password := req.Password
	if password == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("password is required")
	}

	var stmt mongoDBNewUserStatement
	if len(req.Statements.Commands) != 1 {
		return dbplugin.NewUserResponse{}, fmt.Errorf("exactly one creation statement is required to provide the auth database, got %d", len(req.Statements.Commands))
	}
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse creation statement: %w", err)
	}
	if stmt.AuthSource == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("auth database where the target user is defined must be specified in the creation statements")
	}

	var existingUserInfo mongoDBUserInfo
	err := m.client.Database(stmt.AuthSource).RunCommand(ctx, bson.D{
		{
			Key:   "usersInfo",
			Value: userToImpersonate,
		},
	}).Decode(&existingUserInfo)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to query user info of target user %q: %w", userToImpersonate, err)
	}
	if len(existingUserInfo.Users) == 0 {
		return dbplugin.NewUserResponse{}, fmt.Errorf("target user %q not found in database %q", userToImpersonate, stmt.AuthSource)
	}

	err = m.client.Database(stmt.AuthSource).RunCommand(ctx, bson.D{
		{
			Key:   "createUser",
			Value: newUsername,
		},
		{
			Key:   "pwd",
			Value: password,
		},
		{
			Key:   "roles",
			Value: existingUserInfo.Users[0].Roles,
		},
	}).Err()
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create ephemeral user with the roles from the target user %q: %w", userToImpersonate, err)
	}

	return dbplugin.NewUserResponse{
		Username: encodeMongoDBUsername(newUsername, stmt.AuthSource),
	}, nil
}

func (m *mongoDBPlugin) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	username, authDB, err := decodeMongoDBUsername(req.Username)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	err = m.client.Database(authDB).RunCommand(ctx, bson.D{
		{Key: "dropUser", Value: username},
	}).Err()
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to delete ephemeral user %q from authentication database %q: %w", username, authDB, err)
	}

	return dbplugin.DeleteUserResponse{}, nil
}

func (m *mongoDBPlugin) UpdateUser(_ context.Context, _ dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	// The relay does not use UpdateUser at this time. Return stub implementation to satisfy the interface.
	return dbplugin.UpdateUserResponse{}, fmt.Errorf("UpdateUser not implemented for MongoDB plugin")
}

func encodeMongoDBUsername(username, authDB string) string {
	return url.QueryEscape(username) + "@" + authDB
}

func decodeMongoDBUsername(encoded string) (username, authDB string, err error) {
	parts := strings.SplitN(encoded, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid encoded username format: expected 'username@authDB', got %q", encoded)
	}

	decodedUsername, err := url.QueryUnescape(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode username: %w", err)
	}

	return decodedUsername, parts[1], nil
}
