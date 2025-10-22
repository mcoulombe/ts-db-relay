package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all configuration for the ts-db-relay
type Config struct {
	Tailscale TailscaleConfig `json:"tailscale"`
	Relay     RelayConfig     `json:"relay"`
	Database  DatabaseConfig  `json:"database"`
}

// TailscaleConfig holds Tailscale-specific configuration
type TailscaleConfig struct {
	ControlURL string `json:"control_url"`
	Hostname   string `json:"hostname"`
	StateDir   string `json:"state_dir"`
}

// RelayConfig holds relay server configuration
type RelayConfig struct {
	Port      int `json:"port"`
	DebugPort int `json:"debug_port,omitempty"`
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Type          DBType `json:"type"`
	Address       string `json:"address"`
	CAFile        string `json:"ca_file"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Tailscale.StateDir == "" {
		return fmt.Errorf("tailscale.state_dir is required")
	}
	if c.Relay.Port == 0 {
		return fmt.Errorf("relay.port is required")
	}
	if c.Database.Type == "" {
		return fmt.Errorf("database.type is required")
	}
	if c.Database.Address == "" {
		return fmt.Errorf("database.address is required")
	}
	if c.Database.CAFile == "" {
		return fmt.Errorf("database.ca_file is required")
	}
	if c.Database.AdminUser == "" {
		return fmt.Errorf("database.admin_user is required")
	}
	if c.Database.AdminPassword == "" {
		return fmt.Errorf("database.admin_password is required")
	}
	return nil
}
