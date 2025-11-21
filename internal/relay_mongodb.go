package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"tailscale.com/client/local"
	"tailscale.com/metrics"
)

var _ Relay = (*mongoRelay)(nil)

type mongoRelay struct {
	relay
}

func newMongo(dbKey string, dbCfg *DBConfig, tsClient *local.Client) (*mongoRelay, error) {
	dbCA, err := os.ReadFile(dbCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	dbCertPool := x509.NewCertPool()
	if !dbCertPool.AppendCertsFromPEM(dbCA) {
		return nil, fmt.Errorf("invalid CA cert in %q", dbCfg.CAFile)
	}
	relayCert, err := GenerateSelfSignedCert(dbCfg.Host)
	if err != nil {
		return nil, err
	}

	r := &mongoRelay{
		relay: relay{
			dbKey:       dbKey,
			dbEngine:    dbCfg.Engine,
			dbHost:      dbCfg.Host,
			dbPort:      dbCfg.Port,
			dbAdminUser: dbCfg.AdminUser,
			dbAdminPass: dbCfg.AdminPassword,
			dbCertPool:  dbCertPool,
			relayCert:   []tls.Certificate{relayCert},
			tsClient:    tsClient,
			metrics: &relayMetrics{
				errors: metrics.LabelMap{Label: "kind"},
			},
		},
	}
	r.concrete = r

	return r, nil
}

func (r *mongoRelay) handleTLSNegotiation(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return nil, fmt.Errorf("MongoDB relay not yet implemented")
}

func (r *mongoRelay) parseHandshake(conn net.Conn) (string, string, map[string]string, error) {
	return "", "", nil, fmt.Errorf("MongoDB relay not yet implemented")
}

func (r *mongoRelay) createSessionUser(ctx context.Context) error {
	return fmt.Errorf("MongoDB relay not yet implemented")
}

func (r *mongoRelay) deleteSessionUser(ctx context.Context) {
}

func (r *mongoRelay) connectToDatabase(ctx context.Context, params map[string]string) (net.Conn, error) {
	return nil, fmt.Errorf("MongoDB relay not yet implemented")
}

func (r *mongoRelay) sendAuthSuccessToClient(conn net.Conn) error {
	return fmt.Errorf("MongoDB relay not yet implemented")
}

func (r *mongoRelay) proxyConnection(clientConn, dbConn net.Conn, auditFile *os.File) error {
	return fmt.Errorf("MongoDB relay not yet implemented")
}
