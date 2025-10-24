#!/bin/bash
set -e

echo "=== Starting ts-db-relay setup ==="

echo "Running Postgres setup..."
source /setup-postgres.sh

echo "Running CockroachDB setup..."
source /setup-cockroachdb.sh

echo "=== Setup complete ==="
echo "All relays are running. Keeping container alive..."

# Keep container alive - wait for all background processes
wait
