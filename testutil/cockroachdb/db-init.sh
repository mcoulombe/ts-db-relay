#!/bin/bash
set -e

# Wait for CockroachDB to be ready
until cockroach sql --certs-dir=/cockroach/cockroach-certs --host=localhost --execute="SELECT 1" > /dev/null 2>&1; do
    sleep 1
done

# Create admin user
cockroach sql --certs-dir=/cockroach/cockroach-certs --host=localhost <<-EOSQL
CREATE USER IF NOT EXISTS ${COCKROACH_ADMIN_USER} WITH PASSWORD '${COCKROACH_ADMIN_PASSWORD}';
GRANT admin TO ${COCKROACH_ADMIN_USER};
EOSQL

# Create role
cockroach sql --certs-dir=/cockroach/cockroach-certs --host=localhost <<-EOSQL
CREATE USER IF NOT EXISTS ${COCKROACH_ROLE} WITH PASSWORD 'Test4Sk8teboard';
EOSQL

# Create database and grant privileges
cockroach sql --certs-dir=/cockroach/cockroach-certs --host=localhost <<-EOSQL
CREATE DATABASE IF NOT EXISTS ${COCKROACH_DATABASE};
GRANT ALL ON DATABASE ${COCKROACH_DATABASE} TO ${COCKROACH_ROLE};
EOSQL
