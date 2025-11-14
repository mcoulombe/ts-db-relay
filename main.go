package main

import (
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	configFile = flag.String("config", "", "Path to configuration file (JSON or HuJSON format)")
)

func main() {
	flag.Parse()

	// TODO define well-known OS-dependant default locations such as ./.config.json or /etc/ts-db-connector/config.json
	if *configFile == "" {
		log.Fatal("missing --config flag: path to configuration file required")
	}
	rawCfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	config, err := ParseConfig(rawCfg)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	// TODO determine if other Server config fields should be editable via the ts-db-connector config file
	// TODO support client secret and workload identity on top of auth keys to join the tailnet
	tsServer := &tsnet.Server{
		ControlURL: config.Tailscale.ControlURL,
		Hostname:   config.Tailscale.Hostname,
		Dir:        config.Tailscale.StateDir,
		AuthKey:    config.Tailscale.AuthKey,
	}

	tsClient, err := tsServer.LocalClient()
	if err != nil {
		log.Fatalf("unable to instantiate Tailscale Local client: %v", err)
	}

	for dbKey, dbConfig := range config.Databases {
		relay, err := dbConfig.Engine.NewRelay(dbKey, &dbConfig, tsClient)
		if err != nil {
			log.Fatalf("failed to create relay for database %q: %v", dbKey, err)
		}

		expvar.Publish(dbKey, relay.Metrics())

		relayListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", dbConfig.Port))
		if err != nil {
			log.Fatalf("failed to listen on port %d for database %q: %v", dbConfig.Port, dbKey, err)
		}

		log.Printf("serving access to %s (%s) on port %d", dbKey, dbConfig.Host, dbConfig.Port)

		go func(r Relay, l net.Listener, name string) {
			log.Fatalf("relay for database %q ended: %v", name, r.Serve(l))
		}(relay, relayListener, dbKey)
	}

	mux := http.NewServeMux()
	tsweb.Debugger(mux)
	srv := &http.Server{
		Handler: mux,
	}

	adminListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", config.Connector.AdminPort))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Printf("serving admin API on port %d", config.Connector.AdminPort)
		log.Fatal(srv.Serve(adminListener))
	}()

	log.Printf("Database management API available at http://ts-db-connector:%d/debug/", config.Connector.AdminPort)

	select {}
}
