#!/bin/bash
set -e

export PATH="/usr/lib/postgresql/13/bin:$PATH"

PGDATA="/var/lib/postgresql/data"

# Ensure PGDATA directory exists and has correct permissions
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Ensure ts-state directory exists and has correct permissions
mkdir -p /var/lib/ts-state
chmod 755 /var/lib/ts-state

# Create certificates directory
mkdir -p /var/lib/certs
chmod 755 /var/lib/certs

# Generate TLS certificates
echo "Generating TLS certificates..."

# Generate private key
openssl genrsa -out /var/lib/certs/server.key 2048

# Create certificate config with SANs
cat > /var/lib/certs/cert.conf <<EOF
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
openssl req -new -x509 -key /var/lib/certs/server.key -out /var/lib/certs/server.crt -days 365 \
    -config /var/lib/certs/cert.conf -extensions v3_req

# Copy certificate as CA file for client verification
cp /var/lib/certs/server.crt /var/lib/certs/ca.crt

# Set proper permissions
chown -R postgres:postgres /var/lib/certs
chmod 600 /var/lib/certs/server.key
chmod 644 /var/lib/certs/server.crt /var/lib/certs/ca.crt /var/lib/certs/cert.conf

echo "TLS certificates generated with SANs."

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

# Initialize database if empty
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "Initializing Postgres database..."
    su postgres -c "initdb -D $PGDATA"
fi

# Configure Postgres for SSL
echo "Configuring Postgres SSL settings..."
cat >> "$PGDATA/postgresql.conf" <<'EOF'

# SSL Configuration
ssl = on
ssl_cert_file = '/var/lib/certs/server.crt'
ssl_key_file = '/var/lib/certs/server.key'
ssl_ca_file = '/var/lib/certs/ca.crt'
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
echo "Generating admin credentials..."
export DB_ADMIN_USER="relay_admin"
export DB_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
echo "Admin user: $DB_ADMIN_USER"

# Create admin user with CREATEROLE and CREATEDB privileges
echo "Creating/updating admin user..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_ADMIN_USER'
   ) THEN
      CREATE ROLE $DB_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$DB_ADMIN_PASSWORD';
   ELSE
      ALTER ROLE $DB_ADMIN_USER WITH LOGIN CREATEROLE CREATEDB PASSWORD '$DB_ADMIN_PASSWORD';
   END IF;
END
\$do\$;
EOSQL
echo "Admin user '$DB_ADMIN_USER' is ready."

# Create or update test user
echo "Creating/updating test user..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'test'
   ) THEN
      CREATE ROLE test WITH LOGIN PASSWORD 'Test4Sk8board';
   ELSE
      ALTER ROLE test WITH PASSWORD 'Test4Sk8board';
   END IF;
END
\$do\$;
EOSQL
echo "User 'test' is ready."

# Create or update testdb
echo "Creating/updating test db..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
SELECT 'CREATE DATABASE testdb'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'testdb')\gexec
EOSQL
echo "Database 'testdb' is ready."

# Create config directory
mkdir -p /etc/ts-db-relay
chmod 755 /etc/ts-db-relay

# Generate shared config file
echo "Generating config file..."
cat > /etc/ts-db-relay/config.json <<EOF
{
  "tailscale": {
    "control_url": "$TS_SERVER",
    "hostname": "postgres-db",
    "state_dir": "/var/lib/ts-state"
  },
  "database": {
    "type": "postgres",
    "address": "localhost:5432",
    "ca_file": "/var/lib/certs/ca.crt",
    "admin_user": "$DB_ADMIN_USER",
    "admin_password": "$DB_ADMIN_PASSWORD"
  },
  "relay": {
    "port": 5432,
    "debug_port": 80
  }
}
EOF

chmod 600 /etc/ts-db-relay/config.json
echo "Config file created."

# Start DB relay
echo "Starting DB relay..."
TS_AUTHKEY=$TS_AUTHKEY \
/usr/local/bin/ts-db-relay \
--config=/etc/ts-db-relay/config.json \
&

# Create config for dummy relay
cat > /etc/ts-db-relay/dummy-config.json <<EOF
{
  "tailscale": {
    "control_url": "$TS_SERVER",
    "hostname": "dummy",
    "state_dir": "/var/lib/ts-dummy-state"
  },
  "database": {
    "type": "postgres",
    "address": "localhost:5432",
    "ca_file": "/var/lib/certs/ca.crt",
    "admin_user": "$DB_ADMIN_USER",
    "admin_password": "$DB_ADMIN_PASSWORD"
  },
  "relay": {
    "port": 5433,
    "debug_port": 81
  }
}
EOF

chmod 600 /etc/ts-db-relay/dummy-config.json

# Start a dummy relay to prove multiple can live side by side
echo "Starting dummy DB relay..."
TS_AUTHKEY=$TS_AUTHKEY \
/usr/local/bin/ts-db-relay \
--config=/etc/ts-db-relay/dummy-config.json \
&

# Keep container alive
wait -n
