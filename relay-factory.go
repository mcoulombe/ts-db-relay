package main

import (
	"fmt"

	"tailscale.com/client/local"
)

// DBEngine represents a supported database engine
type DBEngine string

const (
	DBEnginePostgres  DBEngine = "postgres"
	DBEngineCockroach          = "cockroachdb"
)

// DefaultPort returns the default port for the database engine
func (e DBEngine) DefaultPort() string {
	switch e {
	case DBEnginePostgres:
		return "5432"
	case DBEngineCockroach:
		return "26257"
	default:
		return ""
	}
}

// NewRelay creates a new Relay implementation based on the database type
func NewRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (Relay, error) {
	switch dbCfg.Type {
	case DBEnginePostgres:
		return newPGWireRelay(dbCfg, tsClient)
	case DBEngineCockroach:
		return newPGWireRelay(dbCfg, tsClient)
	default:
		return nil, fmt.Errorf("database type %q is not supported", dbCfg.Type)
	}
}
