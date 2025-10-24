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

# Wait until CockroachDB is ready
echo "Waiting for CockroachDB to be ready..."
until cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 -e "SELECT 1" > /dev/null 2>&1; do
    echo "Waiting for CockroachDB..."
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
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 <<-EOSQL || echo "CockroachDB admin user setup continuing despite errors..."
CREATE USER IF NOT EXISTS $COCKROACHDB_ADMIN_USER WITH PASSWORD '$COCKROACHDB_ADMIN_PASSWORD';
GRANT admin TO $COCKROACHDB_ADMIN_USER;
EOSQL
echo "CockroachDB admin user '$COCKROACHDB_ADMIN_USER' is ready."

# Create test user
echo "Creating/updating test user..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 <<-EOSQL
CREATE USER IF NOT EXISTS test WITH PASSWORD 'Test4Sk8board';
EOSQL
echo "User 'test' is ready."

# Create client certificate for test user
echo "Creating client certificate for test user..."
cockroach cert create-client test \
    --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key

# Create test database
echo "Creating/updating test database..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost:26257 <<-EOSQL
CREATE DATABASE IF NOT EXISTS testdb;
GRANT ALL ON DATABASE testdb TO test;
SET DATABASE = testdb;
SET client_encoding = 'UTF8';
EOSQL
echo "Database 'testdb' is ready."

# Create config directory
mkdir -p /etc/ts-db-relay
chmod 755 /etc/ts-db-relay

# Generate CockroachDB relay config file
echo "Generating CockroachDB relay config file..."
cat > /etc/ts-db-relay/cockroachdb-config.json <<EOF
{
  "tailscale": {
    "control_url": "$TS_SERVER",
    "hostname": "cockroachdb",
    "state_dir": "/var/lib/cockroachdb-ts-state"
  },
  "database": {
    "type": "cockroachDB",
    "address": "localhost:26257",
    "ca_file": "/var/lib/cockroachdb-certs/ca.crt",
    "admin_user": "$COCKROACHDB_ADMIN_USER",
    "admin_password": "$COCKROACHDB_ADMIN_PASSWORD"
  },
  "relay": {
    "port": 26257,
    "debug_port": 81
  }
}
EOF

chmod 600 /etc/ts-db-relay/cockroachdb-config.json
echo "CockroachDB relay config file created."

# Start CockroachDB relay
echo "Starting CockroachDB relay..."
TS_AUTHKEY=$TS_AUTHKEY /usr/local/bin/ts-db-relay --config=/etc/ts-db-relay/cockroachdb-config.json &
COCKROACHDB_RELAY_PID=$!

echo "CockroachDB setup complete. Relay PID: $COCKROACHDB_RELAY_PID"
