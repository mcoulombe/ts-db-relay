package main

import (
	"expvar"
	"log"
	"net"

	"tailscale.com/metrics"
)

// base provides default implementations of common Relay methods.
// It can be embedded in concrete relay implementations to avoid code duplication.
type base struct {
	metrics *relayMetrics
	// serve is the implementation-specific serve function that handles a single connection
	serve func(net.Conn) error
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
