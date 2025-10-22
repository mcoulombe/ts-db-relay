FROM debian:bullseye-slim

# Install Postgres and dependencies
RUN apt-get update && apt-get install -y \
    postgresql postgresql-contrib bash curl gnupg lsb-release iproute2 iptables ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy setup scripts
COPY entrypoint.sh /entrypoint.sh
COPY setup-postgres.sh /setup-postgres.sh
RUN chmod +x /entrypoint.sh /setup-postgres.sh

CMD ["/entrypoint.sh"]
