package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

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

	if *configFile == "" {
		path, err := internal.DefaultConfigFilePath()
		if err != nil {
			slog.Error("no config file path specified and no default config file found", "error", err)
			os.Exit(1)
		}
		configFile = &path
		slog.Info("using default config file", "file", *configFile)
	}

	rawCfg, err := internal.LoadConfig(*configFile)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
	cfg, err := internal.ParseConfig(rawCfg)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	level, err := internal.ToLogLevel(cfg.Connector.LogLevel)
	if err != nil {
		slog.Error("invalid log level", "level", cfg.Connector.LogLevel, "error", err)
		os.Exit(1)
	}
	slog.SetLogLoggerLevel(level)

	// TODO(max) determine if other Server config fields should be editable via the ts-db-connector config file
	// TODO(gesa) support client secret and workload identity on top of auth keys to join the tailnet
	slog.Info("starting tsnet server...", "tailscale_hostname", cfg.Tailscale.Hostname, "tailscale_control_url", cfg.Tailscale.ControlURL)
	tsServer := &tsnet.Server{
		ControlURL: cfg.Tailscale.ControlURL,
		Hostname:   cfg.Tailscale.Hostname,
		Dir:        cfg.Tailscale.StateDir,
		AuthKey:    cfg.Tailscale.AuthKey,
	}

	if cfg.Connector.TailscaleLogsEnabled {
		slog.Info("enabling tsnet server logs")
		tsServer.Logf = func(format string, args ...any) {
			cur := slog.SetLogLoggerLevel(slog.LevelDebug) // forces log level to DEBUG
			slog.Debug(fmt.Sprintf(format, args...))
			slog.SetLogLoggerLevel(cur)
		}
	}

	conn := internal.NewConnector(cfg)
	if err := conn.Run(ctx, tsServer); err != nil {
		slog.Error("failed to run connector", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	tsweb.Debugger(mux)
	srv := &http.Server{
		Handler: mux,
	}

	adminListener, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", cfg.Connector.AdminPort))
	if err != nil {
		slog.Error("failed to listen on admin port", "port", cfg.Connector.AdminPort, "error", err)
		os.Exit(1)
	}

	go func() {
		slog.Info("admin API available", "url", fmt.Sprintf("http://%s:%d/debug/", cfg.Tailscale.Hostname, cfg.Connector.AdminPort))
		if err := srv.Serve(adminListener); err != nil {
			slog.Error("admin API server failed", "error", err)
			os.Exit(1)
		}
	}()

	select {}
}
