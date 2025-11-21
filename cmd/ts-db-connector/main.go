package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/tailscale/ts-db-connector/internal"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	configFile = flag.String("config", "", "Path to configuration file (JSON or HuJSON format)")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flag.Parse()

	// TODO(max) define well-known OS-dependant default locations such as ./.config.json or /etc/ts-db-connector/config.json
	if *configFile == "" {
		log.Fatal("missing --config flag: path to configuration file required")
	}
	rawCfg, err := internal.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	cfg, err := internal.ParseConfig(rawCfg)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	// TODO(max) determine if other Server config fields should be editable via the ts-db-connector config file
	// TODO(gesa) support client secret and workload identity on top of auth keys to join the tailnet
	tsServer := &tsnet.Server{
		ControlURL: cfg.Tailscale.ControlURL,
		Hostname:   cfg.Tailscale.Hostname,
		Dir:        cfg.Tailscale.StateDir,
		AuthKey:    cfg.Tailscale.AuthKey,
	}

	conn := internal.NewConnector(cfg)
	if err := conn.Run(ctx, tsServer); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	tsweb.Debugger(mux)
	srv := &http.Server{
		Handler: mux,
	}

	adminListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", cfg.Connector.AdminPort))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Printf("serving admin API on port %d", cfg.Connector.AdminPort)
		log.Fatal(srv.Serve(adminListener))
	}()

	log.Printf("Database management API available at http://ts-db-connector:%d/debug/", cfg.Connector.AdminPort)

	select {}
}
