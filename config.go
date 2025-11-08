package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

// Config holds all configuration for the ts-db-connector
type Config struct {
	// Tailscale contains global config fields governing how to interact with the control server
	Tailscale TailscaleConfig `json:"tailscale"`
	// Connector contains global config fields for the main process
	Connector ConnectorConfig `json:"connector"`
	// Databases contain config fields for all database instances the Connector can manage and serve connections to
	Databases map[string]DatabaseConfig `json:"databases"`
}

// TailscaleConfig holds Tailscale-specific configuration
type TailscaleConfig struct {
	// ControlURL is the control server to use when joining the tailnet
	ControlURL string `json:"control_url"`
	// Hostname is the device name to use on the tailnet
	Hostname string `json:"hostname"`
	// StateDir is the directory where to store persistent local data used during reboots
	StateDir string `json:"state_dir"`
}

// ConnectorConfig holds connector server configuration
type ConnectorConfig struct {
	// DebugPort is the HTTP port that serves the debug endpoints
	DebugPort int `json:"debug_port,omitempty"`
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	// Engine is the type of database, e.g. postgres
	Engine DBEngine `json:"engine"`
	// Host is the host where the database instance is located, defaults to localhost
	Host string `json:"host"`
	// Port is the port where the database instance is available, defaults to well-known ports depending on the Engine
	Port int `json:"port"`
	// CAFile is the filename where the certificate to connect to the database instance is located
	CAFile string `json:"ca_file"`
	// TODO remove from the config
	AdminUser string `json:"admin_user"`
	// TODO remove from the config
	AdminPassword string `json:"admin_password"`
}

// LoadConfig loads configuration from a JSON or HuJSON file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	ast, err := hujson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	ast.Standardize()
	data = ast.Pack()

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %v", err)
	}

	// Apply defaults for each database
	for name, db := range config.Databases {
		if db.Host == "" {
			db.Host = "localhost"
		}
		if db.Port == 0 {
			db.Port = db.Engine.DefaultPort()
		}
		config.Databases[name] = db
	}

	return &config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	for name, db := range c.Databases {
		if db.Engine == "" {
			return fmt.Errorf("database %q: type is required", name)
		}
	}
	return nil
}
