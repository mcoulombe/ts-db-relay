package main

import (
	"expvar"
	"net"

	"tailscale.com/metrics"
)

const tsDBRelayCapability = "tailscale.test/cap/ts-db-relay"

// dbCapability represents the access grants for a specific database type
type dbCapability struct {
	Impersonate impersonateSchema `json:"impersonate"`
}

type impersonateSchema struct {
	Databases []string `json:"databases"`
	Roles     []string `json:"roles"`
}

// Relay is used to proxy connections from Tailscale nodes to a database server.
//
// Uses the node's Tailscale identity to authorize access and map it
// to a database user or role, according to the grants defined in the tailnet policy file.
type Relay interface {
	// Serve listens to incoming tailscale connections on the provided listener
	// and proxies each connection to the database server in a separate session.
	Serve(net.Listener) error
	// Metrics returns metrics about the relay's operation which can be consulted on the debug endpoint.
	// Useful for monitoring and debugging.
	Metrics() expvar.Var
}

// relayMetrics holds metrics about the relay's operation
// which can be consulted on the debug endpoint.
type relayMetrics struct {
	// activeSessions is the number of currently active sessions.
	activeSessions expvar.Int
	// startedSessions is the total number of sessions started since the relay began running.
	startedSessions expvar.Int
	// errors is a map of error types to their number of occurrence since the relay began running.
	errors metrics.LabelMap
}
