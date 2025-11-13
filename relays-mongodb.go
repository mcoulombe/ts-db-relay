package main

import (
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"os"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*mongoRelay)(nil)

type mongoRelay struct {
	base

	dbHost      string
	dbPort      int
	dbAdminUser string
	dbAdminPass string
	dbCertPool  *x509.CertPool

	sessionUser     string
	sessionPassword string
	sessionDatabase string
	targetRole      string
}

func newMongoRelay(dbCfg *DatabaseConfig, tsClient *local.Client) (*mongoRelay, error) {
	if dbCfg.CAFile == "" {
		return nil, fmt.Errorf("ca_file is required for MongoDB TLS connections")
	}

	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}

	r := &mongoRelay{
		dbHost:      dbCfg.Host,
		dbPort:      dbCfg.Port,
		dbAdminUser: dbCfg.AdminUser,
		dbAdminPass: dbCfg.AdminPassword,
		dbCertPool:  dbCertPool,
	}

	r.base = base{
		serve:    r.serve,
		tsClient: tsClient,
		metrics: &relayMetrics{
			errors: metrics.LabelMap{Label: "kind"},
		},
	}

	return r, nil
}

func (r *mongoRelay) serve(tsConn net.Conn) error {
	defer tsConn.Close()

	return errors.New("not implemented yet")
}
