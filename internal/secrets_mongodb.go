package internal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBPlugin struct {
	client *mongo.Client
	config map[string]interface{}
}

func New() (dbplugin.Database, error) {
	return &MongoDBPlugin{}, nil
}

func (m *MongoDBPlugin) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	m.config = req.Config

	connectionURL, ok := req.Config["connection_url"].(string)
	if !ok || connectionURL == "" {
		return dbplugin.InitializeResponse{}, fmt.Errorf("connection_url is required")
	}

	var clientOpts *options.ClientOptions
	if opts, ok := req.Config["client_options"].(*options.ClientOptions); ok {
		clientOpts = opts
	} else {
		clientOpts = options.Client().ApplyURI(connectionURL)
	}

	if req.VerifyConnection {
		client, err := mongo.Connect(ctx, clientOpts)
		if err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to connect to MongoDB: %w", err)
		}

		if err := client.Ping(ctx, nil); err != nil {
			client.Disconnect(ctx)
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to ping MongoDB: %w", err)
		}

		m.client = client
	} else {
		client, err := mongo.Connect(ctx, clientOpts)
		if err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to connect to MongoDB: %w", err)
		}
		m.client = client
	}

	return dbplugin.InitializeResponse{
		Config: req.Config,
	}, nil
}

func (m *MongoDBPlugin) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	username := req.UsernameConfig.DisplayName
	if username == "" {
		username = "temp_user"
	}

	username = fmt.Sprintf("%s_%d", username, time.Now().Unix())

	password := req.Password
	if password == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("password is required")
	}

	roles := []bson.M{}
	authDB := "admin"

	for _, cmd := range req.Statements.Commands {
		if cmd != "" {
			roleName := cmd
			dbName := "admin"

			if strings.Contains(cmd, "@") {
				parts := strings.SplitN(cmd, "@", 2)
				roleName = parts[0]
				dbName = parts[1]
				authDB = dbName
			}

			roles = append(roles, bson.M{
				"role": roleName,
				"db":   dbName,
			})
		}
	}

	if len(roles) == 0 {
		roles = append(roles, bson.M{
			"role": "readWrite",
			"db":   "admin",
		})
	}

	targetDB := m.client.Database(authDB)

	createUserCmd := bson.D{
		{Key: "createUser", Value: username},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: roles},
	}

	err := targetDB.RunCommand(ctx, createUserCmd).Err()
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create MongoDB user: %w", err)
	}

	fullUsername := fmt.Sprintf("%s@%s", username, authDB)

	return dbplugin.NewUserResponse{
		Username: fullUsername,
	}, nil
}

func (m *MongoDBPlugin) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password != nil {
		adminDB := m.client.Database("admin")

		updateCmd := bson.D{
			{Key: "updateUser", Value: req.Username},
			{Key: "pwd", Value: req.Password.NewPassword},
		}

		err := adminDB.RunCommand(ctx, updateCmd).Err()
		if err != nil {
			return dbplugin.UpdateUserResponse{}, fmt.Errorf("failed to update MongoDB user password: %w", err)
		}
	}

	return dbplugin.UpdateUserResponse{}, nil
}

func (m *MongoDBPlugin) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	username := req.Username
	dbName := "admin"

	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		dbName = parts[1]
	}

	targetDB := m.client.Database(dbName)

	dropUserCmd := bson.D{
		{Key: "dropUser", Value: username},
	}

	err := targetDB.RunCommand(ctx, dropUserCmd).Err()
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to delete MongoDB user: %w", err)
	}

	return dbplugin.DeleteUserResponse{}, nil
}

func (m *MongoDBPlugin) Type() (string, error) {
	return "mongodb", nil
}

func (m *MongoDBPlugin) Close() error {
	if m.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.client.Disconnect(ctx)
	}
	return nil
}
