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
func (e DBEngine) DefaultPort() int {
	switch e {
	case DBEnginePostgres:
		return 5432
	case DBEngineCockroach:
		return 26257
	default:
		return 0
	}
}

// NewRelay creates a new Relay implementation based on the database type
func NewRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (Relay, error) {
	switch dbCfg.Engine {
	case DBEnginePostgres:
		return newPGWireRelay(dbCfg, tsClient)
	case DBEngineCockroach:
		return newPGWireRelay(dbCfg, tsClient)
	default:
		return nil, fmt.Errorf("database engine %q is not supported", dbCfg.Engine)
	}
}
