#!/bin/bash
set -e

echo "=== Starting ts-db-connector setup ==="

# Parse DB_ENGINES environment variable (defaults to "all")
DB_ENGINES=${DB_ENGINES:-all}

# Convert to lowercase for case-insensitive comparison
DB_ENGINES_LOWER=$(echo "$DB_ENGINES" | tr '[:upper:]' '[:lower:]')

# Function to check if an engine should be started
should_start_engine() {
    local engine=$1
    if [[ "$DB_ENGINES_LOWER" == "all" || "$DB_ENGINES_LOWER" == "*" ]]; then
        return 0
    fi
    if echo "$DB_ENGINES_LOWER" | grep -qw "$engine"; then
        return 0
    fi
    return 1
}

# Start Postgres if requested
if should_start_engine "postgres"; then
    echo "Running Postgres setup..."
    source /setup-postgres.sh
else
    echo "Skipping Postgres setup (not in DB_ENGINES: $DB_ENGINES)"
fi

# Start CockroachDB if requested
if should_start_engine "cockroachdb"; then
    echo "Running CockroachDB setup..."
    source /setup-cockroachdb.sh
else
    echo "Skipping CockroachDB setup (not in DB_ENGINES: $DB_ENGINES)"
fi

echo "=== Setup complete ==="
echo "Database instances are running and config file updated at /workspace/.config.hujson"
echo "You can now run ts-db-connector on your host machine with: ./cmd/ts-db-connector --config=.config.hujson"
echo "Keeping container alive..."

# Keep container alive
tail -f /dev/null
