#!/bin/bash
set -e

# Install dependencies
echo "Installing jq and openssl..."
if ! command -v jq &> /dev/null; then
    apt-get update > /dev/null 2>&1 && apt-get install -y jq openssl > /dev/null 2>&1
fi

# Generate TLS certificates
mkdir -p /var/lib/postgres-certs
chmod 755 /var/lib/postgres-certs

if [ ! -f /var/lib/postgres-certs/server.crt ]; then
    echo "Generating PostgreSQL TLS certificates..."
    openssl genrsa -out /var/lib/postgres-certs/server.key 2048

    cat > /var/lib/postgres-certs/cert.conf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=CA
L=SF
O=Test
OU=Test
CN=localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = postgres
DNS.3 = ts-db-postgres
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    openssl req -new -x509 -key /var/lib/postgres-certs/server.key \
        -out /var/lib/postgres-certs/server.crt -days 365 \
        -config /var/lib/postgres-certs/cert.conf -extensions v3_req

    cp /var/lib/postgres-certs/server.crt /var/lib/postgres-certs/ca.crt
    chown -R postgres:postgres /var/lib/postgres-certs
    chmod 600 /var/lib/postgres-certs/server.key
    chmod 644 /var/lib/postgres-certs/server.crt /var/lib/postgres-certs/ca.crt
else
    echo "PostgreSQL TLS certificates already exist, skipping generation."
fi

# Initialize and configure database
if [ ! -s "/var/lib/postgresql/data/PG_VERSION" ]; then
    echo "Initializing PostgreSQL database..."
    gosu postgres initdb -D /var/lib/postgresql/data
fi

cat > /var/lib/postgresql/data/pg_hba.conf <<'EOF'
local   all             postgres                                trust
local   all             all                                     md5
hostssl all             all             0.0.0.0/0               md5
hostssl all             all             ::/0                    md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
host    all             all             172.16.0.0/12           md5
host    all             all             192.168.0.0/16          md5
EOF

cat >> /var/lib/postgresql/data/postgresql.conf <<'EOF'

listen_addresses = '*'
ssl = on
ssl_cert_file = '/var/lib/postgres-certs/server.crt'
ssl_key_file = '/var/lib/postgres-certs/server.key'
ssl_ca_file = '/var/lib/postgres-certs/ca.crt'
EOF

chown postgres:postgres /var/lib/postgresql/data/pg_hba.conf
chown postgres:postgres /var/lib/postgresql/data/postgresql.conf

# Start database
echo "Starting PostgreSQL..."
docker-entrypoint.sh postgres &
POSTGRES_PID=$!

# Wait for database to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h localhost > /dev/null 2>&1; do
    sleep 2
done
echo "PostgreSQL is ready!"

# Create/update admin user
export POSTGRES_ADMIN_USER="relay_admin"
export POSTGRES_ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo "Admin user: $POSTGRES_ADMIN_USER"

psql -U postgres -d postgres -c "
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_ADMIN_USER') THEN
      CREATE ROLE $POSTGRES_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$POSTGRES_ADMIN_PASSWORD';
   ELSE
      ALTER ROLE $POSTGRES_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$POSTGRES_ADMIN_PASSWORD';
   END IF;
END
\$\$;" > /dev/null

# Create/update test user
export POSTGRES_TEST_USER="${POSTGRES_USER}"
export POSTGRES_TEST_PASSWORD="${POSTGRES_PASSWORD}"
echo "Test user: $POSTGRES_TEST_USER"

psql -U postgres -d postgres -c "
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_TEST_USER') THEN
      CREATE ROLE $POSTGRES_TEST_USER WITH LOGIN PASSWORD '$POSTGRES_TEST_PASSWORD';
   ELSE
      ALTER ROLE $POSTGRES_TEST_USER WITH LOGIN PASSWORD '$POSTGRES_TEST_PASSWORD';
   END IF;
END
\$\$;" > /dev/null

# Create test database and grant privileges
echo "Setting up test database '$POSTGRES_DB'..."
psql -U postgres -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'" | grep -q 1 || \
    psql -U postgres -d postgres -c "CREATE DATABASE $POSTGRES_DB" > /dev/null

psql -U postgres -d "$POSTGRES_DB" -c "
GRANT CONNECT ON DATABASE $POSTGRES_DB TO $POSTGRES_TEST_USER;
GRANT USAGE ON SCHEMA public TO $POSTGRES_TEST_USER;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO $POSTGRES_TEST_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO $POSTGRES_TEST_USER;" > /dev/null

echo "Database '$POSTGRES_DB' ready."

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
   --arg port "5432" \
   --arg ca_file "./data/postgres-certs/ca.crt" \
   --arg admin_user "$POSTGRES_ADMIN_USER" \
   --arg admin_pass "$POSTGRES_ADMIN_PASSWORD" \
   '.databases["my-postgres-1"] = {
       "engine": "postgres",
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
echo "PostgreSQL setup complete."

wait $POSTGRES_PID
