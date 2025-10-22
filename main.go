package main

import (
	"expvar"
	"flag"
	"fmt"
	"log"
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

	config, err := LoadConfig(*configFile)
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

	tsServer := &tsnet.Server{
		ControlURL: controlURL,
		Hostname:   config.Tailscale.Hostname,
		Dir:        config.Tailscale.StateDir,
	}

	tsClient, err := tsServer.LocalClient()
	if err != nil {
		log.Fatalf("unable to instantiate Tailscale Local tsClient: %v", err)
	}

	relay, err := NewRelay(&config.Database, tsClient)
	if err != nil {
		log.Fatal(err)
	}

	expvar.Publish(config.Tailscale.Hostname, relay.Metrics())

	if config.Relay.DebugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		srv := &http.Server{
			Handler: mux,
		}
		debugListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", config.Relay.DebugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Printf("serving debug access to %s on port %d", config.Database.Address, config.Relay.DebugPort)
			log.Fatal(srv.Serve(debugListener))
		}()
	}

	relayListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", config.Relay.Port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving access to %s on port %d", config.Database.Address, config.Relay.Port)
	log.Fatal(relay.Serve(relayListener))
}
