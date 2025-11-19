package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
	"tailscale.com/tailcfg"
)

// base provides default implementations of common Relay methods.
// It can be embedded in concrete relay implementations to avoid code duplication.
type base struct {
	// serve is the protocol-specific serve function that handles a single connection
	serve func(net.Conn) error

	// tsClient is the Tailscale client used for identity verification
	tsClient *local.Client
	// secretsEngine is the OpenBao plugin used to manage users and credentials
	secretsEngine dbplugin.Database
	// metrics holds relay operation metrics
	metrics *relayMetrics
}

// Serve implements the default Serve method that listens for incoming connections
// and delegates each connection to the serve function in a separate goroutine.
func (b *base) Serve(tsListener net.Listener) error {
	for {
		tsConn, err := tsListener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := b.serve(tsConn); err != nil {
				log.Printf("session ended with error: %v", err)
			}
		}()
	}
}

// Metrics implements the default Metrics method that returns relay metrics.
func (b *base) Metrics() expvar.Var {
	ret := &metrics.Set{}
	ret.Set("sessions_active", &b.metrics.activeSessions)
	ret.Set("sessions_started", &b.metrics.startedSessions)
	ret.Set("session_errors", &b.metrics.errors)
	return ret
}

// getClientIdentity extracts user and machine information from Tailscale WhoIs
func (b *base) getClientIdentity(ctx context.Context, conn net.Conn) (string, string, []tailcfg.RawMessage, error) {
	whois, err := b.tsClient.WhoIs(ctx, conn.RemoteAddr().String())
	if err != nil {
		b.metrics.errors.Add("whois-failed", 1)
		return "", "", nil, fmt.Errorf("unexpected error getting client identity: %v", err)
	}

	machine := ""
	if whois.Node != nil {
		if whois.Node.Hostinfo.ShareeNode() {
			machine = "external-device"
		} else {
			machine = strings.TrimSuffix(whois.Node.Name, ".")
		}
	}

	user := ""
	if whois.UserProfile != nil {
		user = whois.UserProfile.LoginName
		if user == "tagged-devices" && whois.Node != nil {
			user = strings.Join(whois.Node.Tags, ",")
		}
	}
	if user == "" || machine == "" {
		b.metrics.errors.Add("no-ts-identity", 1)
		return "", "", nil, fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", user, machine)
	}

	return user, machine, whois.CapMap[tailcfg.PeerCapability(tsDBDatabaseCapability)], nil
}

// hasAccess checks if the given Tailscale identity is authorized to access the specified database
// according to the grants defined in the tailnet policy file.
func (b *base) hasAccess(user, machine, dbKey, dbEngine, sessionDB, sessionRole string, capabilities []tailcfg.RawMessage) (bool, error) {
	if capabilities == nil {
		b.metrics.errors.Add("no-ts-db-database-capability", 1)
		return false, fmt.Errorf("user %q on machine %q does not have ts-db-database capability", user, machine)
	}

	for _, capability := range capabilities {
		var grantCap map[string]dbCapability
		if err := json.Unmarshal([]byte(capability), &grantCap); err != nil {
			b.metrics.errors.Add("capability-parse-error", 1)
			return false, fmt.Errorf("failed to parse capability value: %v", err)
		}

		for capDBKey, dbCap := range grantCap {
			if capDBKey != dbKey {
				continue
			}
			if dbCap.Engine != dbEngine {
				continue
			}

			// Check each access rule in the Access array
			for _, accessRule := range dbCap.Access {
				roleAllowed := false
				for _, allowedRole := range accessRule.Roles {
					if allowedRole == sessionRole {
						roleAllowed = true
						break
					}
				}
				if !roleAllowed {
					continue
				}

				databaseAllowed := false
				for _, allowedDB := range accessRule.Databases {
					if allowedDB == sessionDB {
						databaseAllowed = true
						break
					}
				}
				if !databaseAllowed {
					continue
				}

				return true, nil
			}
		}
	}

	b.metrics.errors.Add("not-allowed-to-impersonate", 1)
	return false, fmt.Errorf("user %q is not allowed to access database %q as role %q", user, sessionDB, sessionRole)
}
