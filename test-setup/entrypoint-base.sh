#!/bin/bash
set -e

echo "=== Starting ts-db-connector setup ==="

# Create default config file if it doesn't exist
mkdir -p /workspace/data
CONFIG_FILE="/workspace/data/.config.hujson"
if [ ! -f "$CONFIG_FILE" ]; then
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
else
    echo "Config file already exists at $CONFIG_FILE"
fi

echo "=== Setup container ready ==="
echo "Database containers will configure themselves and update the config file."
echo "Keeping container alive..."

# Keep container alive
tail -f /dev/null
