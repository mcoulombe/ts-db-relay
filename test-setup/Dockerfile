FROM debian:bookworm-slim

# Install dependencies (just tools needed for setup scripts)
RUN apt-get update && apt-get install -y \
    bash curl gnupg ca-certificates openssl jq \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (needed to run docker exec commands to database containers)
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bookworm stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# Copy setup entrypoint
COPY entrypoint-base.sh /entrypoint-base.sh
RUN chmod +x /entrypoint-base.sh

CMD ["/entrypoint-base.sh"]
