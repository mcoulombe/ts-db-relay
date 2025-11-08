#!/bin/bash
set -e

COCKROACH_DATA="/var/lib/cockroachdb/data"

# Remove existing database to start fresh on each run
echo "Checking CockroachDB data directory..."
if [ -d "$COCKROACH_DATA" ] && [ -n "$(ls -A $COCKROACH_DATA 2>/dev/null)" ]; then
    echo "Cleaning up existing CockroachDB data directory..."
    rm -rf "$COCKROACH_DATA"/*
    echo "CockroachDB data directory cleaned."
fi

# Ensure data directory exists and has correct permissions
mkdir -p "$COCKROACH_DATA"
chmod 755 "$COCKROACH_DATA"

# Ensure cockroachdb tailscale state directory exists and has correct permissions
mkdir -p /var/lib/cockroachdb-ts-state
chmod 755 /var/lib/cockroachdb-ts-state

# Create certificates directory
echo "Checking CockroachDB certificates directory..."
if [ -d "/var/lib/cockroachdb-certs" ] && [ -n "$(ls -A /var/lib/cockroachdb-certs 2>/dev/null)" ]; then
    echo "Cleaning up existing CockroachDB certificates..."
    rm -rf /var/lib/cockroachdb-certs/*
    echo "CockroachDB certificates cleaned."
fi
mkdir -p /var/lib/cockroachdb-certs
chmod 755 /var/lib/cockroachdb-certs

# Create audits directory
mkdir -p /var/lib/cockroachdb-audits
chmod 755 /var/lib/cockroachdb-audits

# Generate CockroachDB TLS certificates
echo "Generating CockroachDB TLS certificates..."

# Create CA certificate
cockroach cert create-ca --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

# Create node certificate for localhost
cockroach cert create-node localhost 127.0.0.1 ::1 cockroachdb \
    --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

# Create client certificate for root user
cockroach cert create-client root --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

echo "CockroachDB TLS certificates generated."

# Start CockroachDB in background
echo "Starting CockroachDB..."
cockroach start-single-node \
    --certs-dir=/var/lib/cockroachdb-certs \
    --store=$COCKROACH_DATA \
    --listen-addr=localhost:26257 \
    --http-addr=localhost:8080 \
    --background

# Give CockroachDB a moment to initialize
sleep 2
echo "CockroachDB background process started, checking if it's accepting connections..."

# Wait until CockroachDB is ready
echo "Waiting for CockroachDB to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0
until timeout 5 cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 --user=root -e "SELECT 1" > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "ERROR: CockroachDB failed to start after $MAX_RETRIES retries"
        echo "Attempting one more connection with verbose output..."
        timeout 5 cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 --user=root -e "SELECT 1" 2>&1 || true
        echo ""
        echo "Checking if CockroachDB process is running..."
        pgrep -a cockroach || echo "No CockroachDB process found"
        echo ""
        echo "Checking CockroachDB logs..."
        tail -50 /var/lib/cockroachdb/data/logs/cockroach.log 2>/dev/null || echo "No logs found"
        exit 1
    fi
    echo "Waiting for CockroachDB (attempt $RETRY_COUNT/$MAX_RETRIES)..."
    sleep 2
done
echo "CockroachDB is ready!"

# Generate random admin password
echo "Generating CockroachDB admin credentials..."
export COCKROACHDB_ADMIN_USER="cockroach_admin"
export COCKROACHDB_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
echo "CockroachDB Admin user: $COCKROACHDB_ADMIN_USER"

# Create client certificate for admin user
echo "Creating client certificate for CockroachDB admin user..."
cockroach cert create-client $COCKROACHDB_ADMIN_USER \
    --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

# Create admin user with admin privileges
echo "Creating/updating CockroachDB admin user..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 --user=root <<-EOSQL || echo "CockroachDB admin user setup continuing despite errors..."
CREATE USER IF NOT EXISTS $COCKROACHDB_ADMIN_USER WITH PASSWORD '$COCKROACHDB_ADMIN_PASSWORD';
GRANT admin TO $COCKROACHDB_ADMIN_USER;
EOSQL
echo "CockroachDB admin user '$COCKROACHDB_ADMIN_USER' is ready."

# Create test user
echo "Creating/updating test user..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 --user=root <<-EOSQL
CREATE USER IF NOT EXISTS $COCKROACH_USER WITH PASSWORD '$COCKROACH_PASSWORD';
EOSQL
echo "User '$COCKROACH_USER' is ready."

# Create client certificate for test user
echo "Creating client certificate for test user..."
cockroach cert create-client $COCKROACH_USER \
    --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

# Create test database
echo "Creating/updating test database..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 --user=root <<-EOSQL
CREATE DATABASE IF NOT EXISTS $COCKROACH_DB;
GRANT ALL ON DATABASE $COCKROACH_DB TO $COCKROACH_USER;
SET DATABASE = $COCKROACH_DB;
SET client_encoding = 'UTF8';
EOSQL
echo "Database '$COCKROACH_DB' is ready."

# Create config directory
mkdir -p /etc/ts-db-connector
chmod 755 /etc/ts-db-connector

# Generate CockroachDB connector config file
echo "Generating CockroachDB connector config file..."
cat > /etc/ts-db-connector/cockroachdb-config.json <<EOF
{
  "tailscale": {
    "control_url": "$TS_SERVER",
    "hostname": "cockroachdb-db",
    "state_dir": "/var/lib/cockroachdb-ts-state"
  },
  "relay": {
      "port": 26257,
      "debug_port": 81
  },
  "database": {
    "name": "my-cockroach-1",
    "type": "cockroachdb",
    "address": "localhost:26257",
    "ca_file": "/var/lib/cockroachdb-certs/ca.crt",
    "admin_user": "$COCKROACHDB_ADMIN_USER",
    "admin_password": "$COCKROACHDB_ADMIN_PASSWORD"
  }
}
EOF

chmod 600 /etc/ts-db-connector/cockroachdb-config.json
echo "CockroachDB connector config file created."

# Start CockroachDB connector
echo "Starting CockroachDB connector..."
TS_AUTHKEY=$TS_AUTHKEY /usr/local/bin/ts-db-connector --config=/etc/ts-db-connector/cockroachdb-config.json &
COCKROACHDB_CONNECTOR_PID=$!

echo "CockroachDB setup complete. Connector PID: $COCKROACHDB_CONNECTOR_PID"
