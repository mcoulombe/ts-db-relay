#!/bin/bash
set -e

# Install dependencies
echo "Installing jq..."
if ! command -v jq &> /dev/null; then
    JQ_VERSION="1.7.1"
    JQ_URL="https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-arm64"
    curl -sL "$JQ_URL" -o /usr/local/bin/jq
    chmod +x /usr/local/bin/jq
fi

# Generate TLS certificates
mkdir -p /var/lib/cockroachdb-certs
chmod 755 /var/lib/cockroachdb-certs

if [ ! -f /var/lib/cockroachdb-certs/ca.crt ]; then
    echo "Generating CockroachDB TLS certificates..."
    cockroach cert create-ca --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key
    cockroach cert create-node localhost cockroachdb ts-db-cockroachdb 127.0.0.1 ::1 \
        --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key
    cockroach cert create-client root --certs-dir=/var/lib/cockroachdb-certs --ca-key=/var/lib/cockroachdb-certs/ca.key
else
    echo "CockroachDB TLS certificates already exist, skipping generation."
fi

# Start database
echo "Starting CockroachDB..."
cockroach start-single-node \
    --certs-dir=/var/lib/cockroachdb-certs \
    --accept-sql-without-tls \
    --listen-addr=0.0.0.0:26257 \
    --http-addr=0.0.0.0:8080 &
COCKROACH_PID=$!

# Wait for database to be ready
echo "Waiting for CockroachDB to be ready..."
until cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost --user=root -e "SELECT 1" > /dev/null 2>&1; do
    sleep 2
done
echo "CockroachDB is ready!"

# Create/update admin user
export COCKROACH_ADMIN_USER="cockroach_admin"
export COCKROACH_ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo "Admin user: $COCKROACH_ADMIN_USER"

cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost --user=root -e "
CREATE USER IF NOT EXISTS $COCKROACH_ADMIN_USER WITH PASSWORD '$COCKROACH_ADMIN_PASSWORD';
ALTER USER $COCKROACH_ADMIN_USER WITH PASSWORD '$COCKROACH_ADMIN_PASSWORD';
GRANT admin TO $COCKROACH_ADMIN_USER;" > /dev/null

# Create/update test user
export COCKROACH_TEST_USER="${COCKROACH_USER}"
export COCKROACH_TEST_PASSWORD="${COCKROACH_PASSWORD}"
echo "Test user: $COCKROACH_TEST_USER"

cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost --user=root -e "
CREATE USER IF NOT EXISTS $COCKROACH_TEST_USER WITH PASSWORD '$COCKROACH_TEST_PASSWORD';
ALTER USER $COCKROACH_TEST_USER WITH PASSWORD '$COCKROACH_TEST_PASSWORD';" > /dev/null

# Create test database and grant privileges
echo "Setting up test database '$COCKROACH_DB'..."
cockroach sql --certs-dir=/var/lib/cockroachdb-certs --host=localhost --user=root -e "
CREATE DATABASE IF NOT EXISTS $COCKROACH_DB;
GRANT ALL ON DATABASE $COCKROACH_DB TO $COCKROACH_TEST_USER;" > /dev/null

echo "Database '$COCKROACH_DB' ready."

# Update config file
CONFIG_FILE="/workspace/data/.config.hujson"

TIMEOUT=30
ELAPSED=0
until [ -f "$CONFIG_FILE" ]; do
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "Error: Timed out waiting for config file after ${TIMEOUT}s"
        echo "The config file '$CONFIG_FILE' should be created by the 'setup' container."
        echo "Make sure the 'setup' service is running: docker compose -f test-setup/compose.yml up setup"
        exit 1
    fi
    echo "Waiting for config file... (${ELAPSED}s/${TIMEOUT}s)"
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

jq --arg host "localhost" \
   --arg port "26257" \
   --arg ca_file "./data/cockroachdb-certs/ca.crt" \
   --arg admin_user "$COCKROACH_ADMIN_USER" \
   --arg admin_pass "$COCKROACH_ADMIN_PASSWORD" \
   '.databases["my-cockroach-1"] = {
       "engine": "cockroachdb",
       "host": $host,
       "port": ($port | tonumber),
       "ca_file": $ca_file,
       "admin_user": $admin_user,
       "admin_password": $admin_pass
   }' "$CONFIG_FILE" > "$CONFIG_FILE.tmp"

if [ $? -ne 0 ]; then
    echo "Error: Failed to update config file"
    exit 1
fi

mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
echo "CockroachDB setup complete."

wait $COCKROACH_PID
