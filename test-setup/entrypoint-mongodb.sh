#!/bin/bash
set -e

# Install dependencies
echo "Installing jq and openssl..."
if ! command -v jq &> /dev/null; then
    apt-get update > /dev/null 2>&1 && apt-get install -y jq openssl > /dev/null 2>&1
fi

# Generate TLS certificates
mkdir -p /etc/ssl/mongodb
chmod 755 /etc/ssl/mongodb

if [ ! -f /etc/ssl/mongodb/server.crt ]; then
    echo "Generating MongoDB TLS certificates..."
    openssl genrsa -out /etc/ssl/mongodb/server.key 2048

    cat > /etc/ssl/mongodb/cert.conf <<EOF
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
DNS.2 = mongodb
DNS.3 = ts-db-mongodb
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    openssl req -new -x509 -key /etc/ssl/mongodb/server.key \
        -out /etc/ssl/mongodb/server.crt -days 365 \
        -config /etc/ssl/mongodb/cert.conf -extensions v3_req

    cat /etc/ssl/mongodb/server.key /etc/ssl/mongodb/server.crt > /etc/ssl/mongodb/mongodb.pem
    cp /etc/ssl/mongodb/server.crt /etc/ssl/mongodb/ca.crt
    chmod 600 /etc/ssl/mongodb/server.key /etc/ssl/mongodb/mongodb.pem
    chmod 644 /etc/ssl/mongodb/server.crt /etc/ssl/mongodb/ca.crt
else
    echo "MongoDB TLS certificates already exist, skipping generation."
fi

# Start database (without TLS for testing)
echo "Starting MongoDB..."
mongod --bind_ip_all &
MONGODB_PID=$!

# Wait for database to be ready
echo "Waiting for MongoDB to be ready..."
until mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; do
    sleep 2
done
echo "MongoDB is ready!"

# Create/update admin user
export MONGODB_ADMIN_USER="mongo_admin"
export MONGODB_ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo "Admin user: $MONGODB_ADMIN_USER"

mongosh admin --eval "
try {
  db.createUser({
    user: '$MONGODB_ADMIN_USER',
    pwd: '$MONGODB_ADMIN_PASSWORD',
    roles: [
      { role: 'userAdminAnyDatabase', db: 'admin' },
      { role: 'dbAdminAnyDatabase', db: 'admin' },
      { role: 'readWriteAnyDatabase', db: 'admin' }
    ]
  });
} catch (e) {
  if (e.code === 51003) {
    db.updateUser('$MONGODB_ADMIN_USER', { pwd: '$MONGODB_ADMIN_PASSWORD' });
  } else {
    throw e;
  }
}" > /dev/null

# Create/update test user
export MONGODB_TEST_USER="${MONGODB_USER}"
export MONGODB_TEST_PASSWORD="${MONGODB_PASSWORD}"
echo "Test user: $MONGODB_TEST_USER"

mongosh -u "$MONGODB_ADMIN_USER" -p "$MONGODB_ADMIN_PASSWORD" \
    --authenticationDatabase admin "$MONGODB_DB" --eval "
try {
  db.createUser({
    user: '$MONGODB_TEST_USER',
    pwd: '$MONGODB_TEST_PASSWORD',
    roles: [ { role: 'readWrite', db: '$MONGODB_DB' } ]
  });
} catch (e) {
  if (e.code === 51003) {
    db.updateUser('$MONGODB_TEST_USER', { pwd: '$MONGODB_TEST_PASSWORD' });
  } else {
    throw e;
  }
}" > /dev/null

echo "Database '$MONGODB_DB' ready."

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
   --arg port "27017" \
   --arg ca_file "./data/mongodb-certs/ca.crt" \
   --arg admin_user "$MONGODB_ADMIN_USER" \
   --arg admin_pass "$MONGODB_ADMIN_PASSWORD" \
   '.databases["my-mongodb-1"] = {
       "engine": "mongodb",
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
echo "MongoDB setup complete."

wait $MONGODB_PID
