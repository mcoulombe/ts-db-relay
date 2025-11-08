FROM debian:bullseye-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    postgresql postgresql-contrib bash curl gnupg lsb-release iproute2 iptables ca-certificates openssl wget jq \
    && rm -rf /var/lib/apt/lists/*

# Install CockroachDB (detect architecture)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        wget -qO- https://binaries.cockroachdb.com/cockroach-v23.1.11.linux-arm64.tgz | tar xvz && \
        cp -i cockroach-v23.1.11.linux-arm64/cockroach /usr/local/bin/ && \
        rm -rf cockroach-v23.1.11.linux-arm64; \
    else \
        wget -qO- https://binaries.cockroachdb.com/cockroach-v23.1.11.linux-amd64.tgz | tar xvz && \
        cp -i cockroach-v23.1.11.linux-amd64/cockroach /usr/local/bin/ && \
        rm -rf cockroach-v23.1.11.linux-amd64; \
    fi

# Copy setup scripts
COPY entrypoint.sh /entrypoint.sh
COPY setup-postgres.sh /setup-postgres.sh
COPY setup-cockroachdb.sh /setup-cockroachdb.sh
RUN chmod +x /entrypoint.sh /setup-postgres.sh /setup-cockroachdb.sh

CMD ["/entrypoint.sh"]
