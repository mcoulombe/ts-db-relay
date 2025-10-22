package main

import (
	"fmt"

	"tailscale.com/client/local"
)

// DBType represents a supported database type
type DBType string

const (
	DBTypePostgres DBType = "postgres"
)

// NewRelay creates a new Relay implementation based on the database type
func NewRelay(dbType DBType, dbAddr, dbCAPath, dbAdminUser, dbAdminPass string, tsClient *local.Client) (Relay, error) {
	switch dbType {
	case DBTypePostgres:
		return newPostgresRelay(dbAddr, dbCAPath, dbAdminUser, dbAdminPass, tsClient)
	default:
		return nil, fmt.Errorf("unsupported database type %q", dbType)
	}
}
