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
	DBEngineMongoDB            = "mongodb"
)

type engineInfo struct {
	defaultPort  int
	newRelayFunc func(string, *DatabaseConfig, *local.Client) (Relay, error)
}

var engines = map[DBEngine]engineInfo{
	DBEnginePostgres: {
		defaultPort: 5432,
		newRelayFunc: func(dbKey string, cfg *DatabaseConfig, client *local.Client) (Relay, error) {
			return newPGWireRelay(dbKey, cfg, client)
		},
	},
	DBEngineCockroach: {
		defaultPort: 26257,
		newRelayFunc: func(dbKey string, cfg *DatabaseConfig, client *local.Client) (Relay, error) {
			return newPGWireRelay(dbKey, cfg, client)
		},
	},
	DBEngineMongoDB: {
		defaultPort: 27017,
		newRelayFunc: func(dbKey string, cfg *DatabaseConfig, client *local.Client) (Relay, error) {
			return newMongoRelay(dbKey, cfg, client)
		},
	},
}

// IsValid returns an error if the engine is not a supported database engine
func (e DBEngine) IsValid() error {
	if _, ok := engines[e]; !ok {
		return fmt.Errorf("unsupported engine %q", e)
	}
	return nil
}

// DefaultPort returns the default port for the database engine
func (e DBEngine) DefaultPort() int {
	info, ok := engines[e]
	if !ok {
		return 0
	}
	return info.defaultPort
}

// NewRelay creates a new Relay implementation for the database engine
func (e DBEngine) NewRelay(dbKey string, dbCfg *DatabaseConfig, tsClient *local.Client) (Relay, error) {
	info, ok := engines[e]
	if !ok {
		return nil, fmt.Errorf("unsupported engine %q", e)
	}
	return info.newRelayFunc(dbKey, dbCfg, tsClient)
}
