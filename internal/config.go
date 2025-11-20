package internal

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

const (
	defaultControlURL = "https://login.tailscale.com"
	defaultStateDir   = "../data/ts-db-connector"
	defaultHostname   = "ts-db-connector"
	defaultAdminPort  = 8080
	defaultHost       = "localhost"
)

var hostnameRegex = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

var wellKnownEnvVars = map[string]string{
	"tailscale.control_url":   "TS_SERVER",
	"tailscale.state_dir":     "TS_STATE_DIR",
	"tailscale.hostname":      "TS_HOSTNAME",
	"tailscale.auth_key":      "TS_AUTHKEY",
	"tailscale.client_id":     "TS_CLIENT_ID",
	"tailscale.client_secret": "TS_CLIENT_SECRET",
	"tailscale.id_token":      "ID_TOKEN",
}

// Config contains all settings for the ts-db-connector.
// It is loaded at startup from the file specified by the --config flag.
// Scalar fields may also be supplied via environment variables (using the 'env:' prefix)
// or file references (using the 'file:' prefix). These mechanisms are useful for securely
// providing sensitive values such as passwords or auth keys.
type Config struct {
	// Tailscale contains global config fields governing how to interact with the control server
	Tailscale TailscaleConfig `json:"tailscale"`
	// Connector contains global config fields for the main process
	Connector ServerConfig `json:"connector"`
	// Databases contain config fields for all database instances the Connector can manage and serve connections to
	Databases map[string]DBConfig `json:"databases"`
}

// TailscaleConfig holds Tailscale-specific configuration.
type TailscaleConfig struct {
	// ControlURL is the control server to use when joining the tailnet
	// Defaults to $TS_SERVER or "https://login.tailscale.com/"
	ControlURL string `json:"control_url"`
	// StateDir is the directory where to store persistent local data
	// Defaults to $TS_STATE_DIR or "./data/ts-db-connector"
	StateDir string `json:"state_dir"`
	// Hostname is the hostname to use when joining the tailnet
	// Defaults to $TS_HOSTNAME or "ts-db-connector"
	Hostname string `json:"hostname"`

	// AuthKey is the Tailscale auth key to use when joining the tailnet
	// Can also be provided via the TS_AUTHKEY environment variable
	AuthKey string `json:"authkey"`
	// ClientID is the auth client ID to use when joining the tailnet via OAuth or Workload Identity
	// Can also be provided via the TS_CLIENT_ID environment variable
	ClientID string `json:"client_id"`
	// ClientSecret is the auth client secret to use when joining the tailnet via OAuth
	// Can also be provided via the TS_CLIENT_SECRET environment variable
	ClientSecret string `json:"client_secret"`
	// IDToken is the ID token to use when joining the tailnet via Workload Identity
	// Can also be provided via the ID_TOKEN environment variable
	IDToken string `json:"id_token"`
}

// ServerConfig holds connector server configuration
type ServerConfig struct {
	// AdminPort is the HTTP port that serves the debug endpoints
	// Defaults to 8080
	AdminPort int `json:"admin_port,omitzero"`
}

// DBConfig holds database connection configuration
type DBConfig struct {
	// Engine is the type of database, e.g. postgres
	Engine DBEngine `json:"engine"`

	// Host is the host where the database instance is located, defaults to localhost
	// Defaults to "localhost"
	Host string `json:"host"`
	// Port is the port where the database instance is available, defaults to well-known ports depending on the Engine
	// Defaults to well-known ports for the engine such as 5432 for Postgres, 27017 for MongoDB, etc.
	Port int `json:"port"`
	// ListeningPort is the port where the connector will listen for incoming Tailscale connections for this database
	// Defaults to the same value as Port
	ListeningPort int `json:"listening_port"`

	// CAFile is the filename where the certificate the connector must use to connect to the database instance is located
	CAFile string `json:"ca_file"`
	// AdminUser is the user the connector uses, along with the AdminPassword, to manage dynamic users
	AdminUser string `json:"admin_user"`
	// AdminPassword is the password the connector uses, along with the AdminUser, to manage dynamic users
	AdminPassword string `json:"admin_password"`
}

// LoadConfig loads configuration from a JSON or HuJSON file
func LoadConfig(path string) ([]byte, error) {
	rawCfg, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	return rawCfg, nil
}

// ParseConfig parses configuration from raw JSON or HuJSON data and performs value resolution and validation
func ParseConfig(rawCfg []byte) (*Config, error) {
	ast, err := hujson.Parse(rawCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	ast.Standardize()

	var config Config
	if err := json.Unmarshal(ast.Pack(), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %v", err)
	}

	if err := config.resolveValues(); err != nil {
		return nil, err
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *Config) resolveValues() error {
	var err error

	c.Tailscale.ControlURL, err = resolveValueFromReference(c.Tailscale.ControlURL, "tailscale.control_url")
	if err != nil {
		return err
	}
	if c.Tailscale.ControlURL == "" {
		c.Tailscale.ControlURL = defaultControlURL
	}

	c.Tailscale.StateDir, err = resolveValueFromReference(c.Tailscale.StateDir, "tailscale.state_dir")
	if err != nil {
		return err
	}
	if c.Tailscale.StateDir == "" {
		c.Tailscale.StateDir = defaultStateDir
	}

	c.Tailscale.Hostname, err = resolveValueFromReference(c.Tailscale.Hostname, "tailscale.hostname")
	if err != nil {
		return err
	}
	if c.Tailscale.Hostname == "" {
		c.Tailscale.Hostname = defaultHostname
	}

	c.Tailscale.AuthKey, err = resolveValueFromReference(c.Tailscale.AuthKey, "tailscale.auth_key")
	if err != nil {
		return err
	}

	c.Tailscale.ClientID, err = resolveValueFromReference(c.Tailscale.ClientID, "tailscale.client_id")
	if err != nil {
		return err
	}

	c.Tailscale.ClientSecret, err = resolveValueFromReference(c.Tailscale.ClientSecret, "tailscale.client_secret")
	if err != nil {
		return err
	}

	c.Tailscale.IDToken, err = resolveValueFromReference(c.Tailscale.IDToken, "tailscale.id_token")
	if err != nil {
		return err
	}

	c.Connector.AdminPort, err = resolveValueFromReference(c.Connector.AdminPort, "connector.admin_port")
	if err != nil {
		return err
	}
	if c.Connector.AdminPort == 0 {
		c.Connector.AdminPort = defaultAdminPort
	}

	for name, db := range c.Databases {
		db.Host, err = resolveValueFromReference(db.Host, fmt.Sprintf("databases.%s.host", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}
		if db.Host == "" {
			db.Host = defaultHost
		}

		db.Port, err = resolveValueFromReference(db.Port, fmt.Sprintf("databases.%s.port", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}
		if db.Port == 0 {
			db.Port = db.Engine.DefaultPort()
		}

		db.ListeningPort, err = resolveValueFromReference(db.ListeningPort, fmt.Sprintf("databases.%s.listening_port", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}
		if db.ListeningPort == 0 {
			db.ListeningPort = db.Port
		}

		db.CAFile, err = resolveValueFromReference(db.CAFile, fmt.Sprintf("databases.%s.ca_file", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}

		db.AdminUser, err = resolveValueFromReference(db.AdminUser, fmt.Sprintf("databases.%s.admin_user", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}

		db.AdminPassword, err = resolveValueFromReference(db.AdminPassword, fmt.Sprintf("databases.%s.admin_password", name))
		if err != nil {
			return fmt.Errorf("database %q: %w", name, err)
		}

		c.Databases[name] = db
	}

	return nil
}

func (c *Config) validate() error {
	if c.Tailscale.ControlURL == "" {
		return fmt.Errorf("tailscale.control_url is required")
	}
	if err := validateControlURL(c.Tailscale.ControlURL); err != nil {
		return fmt.Errorf("tailscale.control_url: %w", err)
	}

	if c.Tailscale.StateDir == "" {
		return fmt.Errorf("tailscale.state_dir is required")
	}
	if err := validateStateDir(c.Tailscale.StateDir); err != nil {
		return fmt.Errorf("tailscale.state_dir: %w", err)
	}

	if c.Tailscale.Hostname == "" {
		return fmt.Errorf("tailscale.hostname is required")
	}
	if err := validateHostname(c.Tailscale.Hostname); err != nil {
		return fmt.Errorf("tailscale.hostname: %w", err)
	}

	if c.Tailscale.AuthKey == "" && c.Tailscale.ClientID == "" && c.Tailscale.ClientSecret == "" && c.Tailscale.IDToken == "" {
		// TODO(max) log in debug once we have a proper debugger setup
		//log.Printf("Warning: No authentication credentials provided (auth_key, client_id, client_secret, or id_token). This is only acceptable if already connected to the tailnet.")
	}

	if c.Connector.AdminPort == 0 {
		return fmt.Errorf("connector.admin_port is required")
	}
	if err := validatePort(c.Connector.AdminPort); err != nil {
		return fmt.Errorf("connector.admin_port: %w", err)
	}

	for name, db := range c.Databases {
		if db.Engine == "" {
			return fmt.Errorf("database %q: engine is required", name)
		}
		if err := validateEngine(db.Engine); err != nil {
			return fmt.Errorf("database %q: engine: %w", name, err)
		}

		if db.Host == "" {
			return fmt.Errorf("database %q: host is required", name)
		}

		if db.Port == 0 {
			return fmt.Errorf("database %q: port is required", name)
		}
		if err := validatePort(db.Port); err != nil {
			return fmt.Errorf("database %q: port: %w", name, err)
		}

		if db.ListeningPort == 0 {
			return fmt.Errorf("database %q: listening_port is required", name)
		}
		if err := validatePort(db.ListeningPort); err != nil {
			return fmt.Errorf("database %q: listening_port: %w", name, err)
		}

		if db.CAFile == "" {
			return fmt.Errorf("database %q: ca_file is required", name)
		}
		if err := validateCAFile(db.CAFile); err != nil {
			return fmt.Errorf("database %q: ca_file: %w", name, err)
		}

		if db.AdminUser == "" {
			return fmt.Errorf("database %q: admin_user is required", name)
		}
		if db.AdminPassword == "" {
			return fmt.Errorf("database %q: admin_password is required", name)
		}
	}

	return nil
}

func validateControlURL(controlURL string) error {
	parsedURL, err := url.Parse(controlURL)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("must have a host")
	}
	if strings.HasSuffix(controlURL, "/") {
		return fmt.Errorf("must not have a trailing slash")
	}
	return nil
}

func validateStateDir(stateDir string) error {
	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("unable to resolve absolute path: %w", err)
	}
	if err := os.MkdirAll(absStateDir, 0700); err != nil {
		return fmt.Errorf("unable to create directory: %w", err)
	}
	return nil
}

func validateHostname(hostname string) error {
	if len(hostname) == 0 || len(hostname) > 63 {
		return fmt.Errorf("must be between 1 and 63 characters long")
	}
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("must start and end with a letter, and consist of only letters, numbers, and hyphens")
	}
	return nil
}

func validatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("must be between 0 and 65535, got %d", port)
	}

	return nil
}

func validateEngine(engine DBEngine) error {
	return engine.IsValid()
}

func validateCAFile(caFile string) error {
	absCAFile, err := filepath.Abs(caFile)
	if err != nil {
		return fmt.Errorf("unable to resolve absolute path: %w", err)
	}
	info, err := os.Stat(absCAFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist")
		}
		return fmt.Errorf("unable to access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file")
	}
	return nil
}

func resolveValueFromReference[T string | int](v T, fieldKey string) (T, error) {
	var zero T
	var strValue string

	switch val := any(v).(type) {
	case string:
		strValue = val
	case int:
		if val != 0 {
			return v, nil
		}
		strValue = ""
	}

	result, err := resolveValueFromFile(strValue)
	if err != nil {
		return zero, err
	}

	result, err = resolveValueFromEnv(result)
	if err != nil {
		return zero, err
	}

	if result == "" && fieldKey != "" {
		if envVar, ok := wellKnownEnvVars[fieldKey]; ok {
			if envValue := os.Getenv(envVar); envValue != "" {
				result = envValue
			}
		}
	}

	switch any(zero).(type) {
	case string:
		return any(result).(T), nil
	case int:
		if result == "" {
			return zero, nil
		}
		intValue, err := strconv.Atoi(result)
		if err != nil {
			return zero, fmt.Errorf("invalid integer value %q for %s: %w", result, fieldKey, err)
		}
		return any(intValue).(T), nil
	default:
		return zero, fmt.Errorf("unsupported type for resolveValueFromReference")
	}
}

func resolveValueFromFile(v string) (string, error) {
	if file, ok := strings.CutPrefix(v, "file:"); ok {
		value, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("unable to read file %q used as config field reference: %v", file, err)
		}
		return strings.TrimSpace(string(value)), nil
	}
	return v, nil
}

func resolveValueFromEnv(v string) (string, error) {
	if env, ok := strings.CutPrefix(v, "env:"); ok {
		value, ok := os.LookupEnv(env)
		if !ok {
			return "", fmt.Errorf("unable to look up environment variable %q used as config field reference", env)
		}
		return strings.TrimSpace(value), nil
	}
	return v, nil
}
