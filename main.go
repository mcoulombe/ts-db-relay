package main

import (
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	configFile = flag.String("config", "", "Path to configuration file (JSON format)")
)

func main() {
	flag.Parse()

	if *configFile == "" {
		log.Fatal("missing --config flag: path to configuration file required")
	}

	config, err := LoadConfigFromFile(*configFile)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	if os.Getenv("TS_AUTHKEY") == "" {
		log.Print("Note: you need to run this with TS_AUTHKEY=... the first time, to join your tailnet of choice.")
	}

	controlURL := config.Tailscale.ControlURL
	if controlURL == "" {
		controlURL = "https://login.tailscale.com/"
	}

	localStorageDir := config.Tailscale.LocalStorageDir
	if localStorageDir == "" {
		localStorageDir = "./data/ts-state"
	}

	tsServer := &tsnet.Server{
		ControlURL: controlURL,
		Hostname:   "ts-db-connector",
		Dir:        localStorageDir,
	}

	tsClient, err := tsServer.LocalClient()
	if err != nil {
		log.Fatalf("unable to instantiate Tailscale Local client: %v", err)
	}

	for dbName, dbConfig := range config.Databases {
		relay, err := NewRelay(&dbConfig, tsClient)
		if err != nil {
			log.Fatalf("failed to create relay for database %q: %v", dbName, err)
		}

		expvar.Publish(dbName, relay.Metrics())

		relayListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", dbConfig.Port))
		if err != nil {
			log.Fatalf("failed to listen on port %d for database %q: %v", dbConfig.Port, dbName, err)
		}

		log.Printf("serving access to %s (%s) on port %d", dbName, dbConfig.Host, dbConfig.Port)

		go func(r Relay, l net.Listener, name string) {
			log.Fatalf("relay for database %q ended: %v", name, r.Serve(l))
		}(relay, relayListener, dbName)
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
