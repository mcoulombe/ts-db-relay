#!/bin/bash
set -e

mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale

# Install Tailscale
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
TAILSCALED_PID=$!
sleep 2

# Have the MCP server container join the tailnet
tailscale up --authkey="${TS_AUTHKEY}" --login-server="${TS_SERVER}" --hostname=cockroach-db-mcp-server --accept-routes

# Start the MCP server
cd /app
exec uv run python src/main.py
