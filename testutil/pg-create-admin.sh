#!/bin/bash
set -e

# Create admin user with CREATEROLE and CREATEDB privileges.
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
