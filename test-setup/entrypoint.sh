#!/bin/bash
set -e

echo "=== Starting ts-db-connector setup ==="

echo "Running Postgres setup..."
source /setup-postgres.sh

echo "Running CockroachDB setup..."
source /setup-cockroachdb.sh

echo "=== Setup complete ==="
echo "All database instances are running and configured on the ts-db-connector process. Keeping container alive..."

# Keep container alive - wait for all background processes
wait
