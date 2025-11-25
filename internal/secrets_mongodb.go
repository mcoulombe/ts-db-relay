package internal

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

type MongoDBPlugin struct{}

func New() (dbplugin.Database, error) {
	return &MongoDBPlugin{}, nil
}

func (m *MongoDBPlugin) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	return dbplugin.InitializeResponse{}, fmt.Errorf("MongoDB secrets engine not yet implemented")
}

func (m *MongoDBPlugin) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	return dbplugin.NewUserResponse{}, fmt.Errorf("MongoDB secrets engine not yet implemented")
}

func (m *MongoDBPlugin) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	return dbplugin.UpdateUserResponse{}, fmt.Errorf("MongoDB secrets engine not yet implemented")
}

func (m *MongoDBPlugin) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	return dbplugin.DeleteUserResponse{}, fmt.Errorf("MongoDB secrets engine not yet implemented")
}

func (m *MongoDBPlugin) Type() (string, error) {
	return "mongodb", nil
}

func (m *MongoDBPlugin) Close() error {
	return nil
}
