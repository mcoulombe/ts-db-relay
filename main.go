package main

import (
	"context"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	connector := &Connector{
		config: config,
	}
	if err := connector.Run(ctx, tsServer); err != nil {
		log.Fatal(err)
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
