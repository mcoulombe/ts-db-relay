package main

import (
	"fmt"

	"tailscale.com/client/local"
)

// DBType represents a supported database type
type DBType string

const (
	DBTypePostgres  DBType = "postgres"
	DBTypeCockroach        = "cockroachDB"
)

// NewRelay creates a new Relay implementation based on the database type
func NewRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (Relay, error) {
	switch dbCfg.Type {
	case DBTypePostgres:
		return newPGWireRelay(dbCfg, tsClient)
	case DBTypeCockroach:
		return newPGWireRelay(dbCfg, tsClient)
	default:
		return nil, fmt.Errorf("unsupported database type %q", dbCfg.Type)
	}
}
