package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all configuration for the ts-db-connector
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
	Type          DBEngine `json:"type"`
	Address       string   `json:"address"`
	CAFile        string   `json:"ca_file"`
	AdminUser     string   `json:"admin_user"`
	AdminPassword string   `json:"admin_password"`
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
	if c.Database.Type == "" {
		return fmt.Errorf("database.type is required")
	}
	return nil
}
