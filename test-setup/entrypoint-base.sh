#!/bin/bash
set -e

echo "=== Starting ts-db-connector setup ==="

# Create default config file
mkdir -p /workspace/data
CONFIG_FILE="/workspace/data/.config.hujson"

if [ -f "$CONFIG_FILE" ]; then
    echo "Clearing existing database instances from config file..."
    jq '.databases = {}' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
    echo "Database instances cleared."
else
    echo "Creating default config file at $CONFIG_FILE..."
    cat > "$CONFIG_FILE" <<EOF
{
  "tailscale": {
    "control_url": "${TS_CONTROL_URL:-http://localhost:31544}",
    "local_storage_dir": "${TS_LOCAL_STORAGE_DIR:-./data/ts-state}"
  },
  "connector": {
    "admin_port": ${TS_ADMIN_PORT:-8080}
  },
  "databases": {}
}
EOF
    echo "Default config file created."
fi

echo "=== Setup container ready ==="
echo "Database containers can now start and configure themselves."
echo "Keeping container alive..."

# Keep container alive
tail -f /dev/null
