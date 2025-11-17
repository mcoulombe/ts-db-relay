#!/bin/bash
set -e

# Create or update role to be assumed by users connecting via the relay.
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
echo "Creating/updating role..."
psql -v ON_ERROR_STOP=1 -U postgres <<-EOSQL
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_ROLE'
   ) THEN
      CREATE ROLE $POSTGRES_ROLE WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
   ELSE
      ALTER ROLE $POSTGRES_ROLE WITH PASSWORD '$POSTGRES_PASSWORD';
   END IF;
END
\$do\$;
EOSQL
echo "Role '$POSTGRES_ROLE' is ready."
