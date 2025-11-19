package main

import (
	"context"
	"expvar"
	"fmt"
	"log"
	"net"
	"sync"

	"tailscale.com/tsnet"
)

type Connector struct {
	config *Config
}

func (c *Connector) Run(ctx context.Context, s *tsnet.Server) error {
	var wg sync.WaitGroup
	var listeners []net.Listener

	lc, err := s.LocalClient()
	if err != nil {
		return err
	}

	for dbKey, dbConfig := range c.config.Databases {
		relay, err := dbConfig.Engine.NewRelay(dbKey, &dbConfig, lc)
		if err != nil {
			return fmt.Errorf("failed to create relay for %q: %w", dbKey, err)
		}
		expvar.Publish(dbKey, relay.Metrics())

		relayListener, err := s.Listen("tcp", fmt.Sprintf(":%d", dbConfig.Port))
		if err != nil {
			return fmt.Errorf("failed to listen on port %d for %q: %w", dbConfig.Port, dbKey, err)
		}
		listeners = append(listeners, relayListener)

		wg.Add(1)
		go func(r Relay, l net.Listener, name string) {
			defer wg.Done()
			if err := r.Serve(l); err != nil {
				log.Printf("Relay for %q ended: %v", name, err)
			}
		}(relay, relayListener, dbKey)
	}

	go func() {
		<-ctx.Done()
		for _, l := range listeners {
			l.Close()
		}
		wg.Wait()
	}()

	return nil
}
