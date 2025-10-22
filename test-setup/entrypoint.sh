#!/bin/bash
set -e

echo "=== Starting ts-db-relay setup ==="

# Run Postgres setup
if [ -f /setup-postgres.sh ]; then
    echo "Running Postgres setup..."
    source /setup-postgres.sh
fi

# Future database setups can be added here
# if [ -f /setup-cockroach.sh ]; then
#     echo "Running CockroachDB setup..."
#     source /setup-cockroach.sh
# fi

echo "=== Setup complete ==="
echo "All relays are running. Keeping container alive..."

# Keep container alive - wait for all background processes
wait
