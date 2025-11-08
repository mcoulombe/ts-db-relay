#!/bin/bash
set -e

export PATH="/usr/lib/postgresql/13/bin:$PATH"

PGDATA="/var/lib/postgresql/data"

# Remove existing database to start fresh on each run
echo "Checking Postgres data directory..."
if [ -d "$PGDATA" ] && [ -n "$(ls -A $PGDATA 2>/dev/null)" ]; then
    echo "Cleaning up existing Postgres data directory..."
    rm -rf "$PGDATA"/*
    echo "Postgres data directory cleaned."
fi

# Ensure PGDATA directory exists and has correct permissions
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Ensure postgres tailscale state directory exists and has correct permissions
mkdir -p /var/lib/postgres-ts-state
chmod 755 /var/lib/postgres-ts-state

# Create certificates directory
mkdir -p /var/lib/postgres-certs
chmod 755 /var/lib/postgres-certs

# Create audits directory
mkdir -p /var/lib/postgres-audits
chmod 755 /var/lib/postgres-audits

# Generate Postgres TLS certificates
echo "Generating Postgres TLS certificates..."

# Generate private key
openssl genrsa -out /var/lib/postgres-certs/server.key 2048

# Create certificate config with SANs
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
DNS.2 = postgres-db
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate certificate with SANs
openssl req -new -x509 -key /var/lib/postgres-certs/server.key -out /var/lib/postgres-certs/server.crt -days 365 \
    -config /var/lib/postgres-certs/cert.conf -extensions v3_req

# Copy certificate as CA file for client verification
cp /var/lib/postgres-certs/server.crt /var/lib/postgres-certs/ca.crt

# Set proper permissions
chown -R postgres:postgres /var/lib/postgres-certs
chmod 600 /var/lib/postgres-certs/server.key
chmod 644 /var/lib/postgres-certs/server.crt /var/lib/postgres-certs/ca.crt /var/lib/postgres-certs/cert.conf

echo "Postgres TLS certificates generated with SANs."

echo "Initializing Postgres database..."
su postgres -c "initdb -D $PGDATA"

# Write a secure pg_hba.conf that forces password auth and SSL
cat > "$PGDATA/pg_hba.conf" <<'EOF'
local   all             postgres                                trust
local   all             all                                     md5
hostssl all             all             127.0.0.1/32            md5
hostssl all             all             ::1/128                 md5
hostssl all             all             0.0.0.0/0               md5
EOF

# Ensure correct permissions
chown postgres:postgres "$PGDATA/pg_hba.conf"

# Configure Postgres for SSL
echo "Configuring Postgres SSL settings..."
cat >> "$PGDATA/postgresql.conf" <<'EOF'

# SSL Configuration
ssl = on
ssl_cert_file = '/var/lib/postgres-certs/server.crt'
ssl_key_file = '/var/lib/postgres-certs/server.key'
ssl_ca_file = '/var/lib/postgres-certs/ca.crt'
EOF

chown postgres:postgres "$PGDATA/postgresql.conf"

# Start Postgres in background
echo "Starting Postgres..."
su postgres -c "postgres -D $PGDATA &"

# Wait until Postgres is ready
until pg_isready -h localhost -p 5432; do
    echo "Waiting for Postgres..."
    sleep 1
done
echo "Postgres is ready!"

# Generate random admin password
echo "Generating Postgres admin credentials..."
export POSTGRES_ADMIN_USER="relay_admin"
export POSTGRES_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
echo "Postgres Admin user: $POSTGRES_ADMIN_USER"

# Create admin user with CREATEROLE and CREATEDB privileges
echo "Creating/updating Postgres admin user..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_ADMIN_USER'
   ) THEN
      CREATE ROLE $POSTGRES_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$POSTGRES_ADMIN_PASSWORD';
   ELSE
      ALTER ROLE $POSTGRES_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$POSTGRES_ADMIN_PASSWORD';
   END IF;
END
\$do\$;
EOSQL
echo "Postgres admin user '$POSTGRES_ADMIN_USER' is ready."

# Create or update test user
echo "Creating/updating test user..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_USER'
   ) THEN
      CREATE ROLE $POSTGRES_USER WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
   ELSE
      ALTER ROLE $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';
   END IF;
END
\$do\$;
EOSQL
echo "User '$POSTGRES_USER' is ready."

# Create or update test database
echo "Creating/updating test database..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
SELECT 'CREATE DATABASE $POSTGRES_DB'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB')\gexec
EOSQL
echo "Database '$POSTGRES_DB' is ready."

# Create config directory
mkdir -p /etc/ts-db-connector
chmod 755 /etc/ts-db-connector

# Generate shared config file
echo "Generating Postgres connector config file..."
cat > /etc/ts-db-connector/postgres-config.json <<EOF
{
  "tailscale": {
    "control_url": "$TS_SERVER",
    "hostname": "postgres-db",
    "state_dir": "/var/lib/postgres-ts-state"
  },
  "relay": {
      "port": 5432,
      "debug_port": 80
  },
  "database": {
    "name": "my-postgres-1",
    "type": "postgres",
    "address": "localhost:5432",
    "ca_file": "/var/lib/postgres-certs/ca.crt",
    "admin_user": "$POSTGRES_ADMIN_USER",
    "admin_password": "$POSTGRES_ADMIN_PASSWORD"
  }
}
EOF

chmod 600 /etc/ts-db-connector/postgres-config.json
echo "Postgres connector config file created."

# Start Postgres connector
echo "Starting Postgres connector..."
TS_AUTHKEY=$TS_AUTHKEY /usr/local/bin/ts-db-connector --config=/etc/ts-db-connector/postgres-config.json &
POSTGRES_CONNECTOR_PID=$!

echo "Postgres setup complete. Connector PID: $POSTGRES_CONNECTOR_PID"
