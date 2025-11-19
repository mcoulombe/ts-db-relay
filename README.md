# ts-db-connector

A [tsnet](https://tailscale.com/kb/1244/tsnet) application letting Tailscale nodes access databases from anywhere using their Tailscale identity to authenticate.

## Usage

The ts-db-connector is a [tsnet](https://tailscale.com/kb/1244/tsnet) application that runs as a single Tailscale node and proxies database connections over your tailnet.

### Configuration File

Configuration is stored in HuJSON format (JSON with comments) and loaded via the `--config` flag. Field values can reference environment variables using the `env:` prefix or files using the `file:` prefix.

#### Tailscale Configuration

| Field           | Purpose                                                                  | Default                       | Well-known Env Var |
|-----------------|--------------------------------------------------------------------------|-------------------------------|--------------------|
| `control_url`   | Tailscale control server URL (must be http/https without trailing slash) | `https://login.tailscale.com` | `TS_SERVER`        |
| `state_dir`     | Directory for persistent Tailscale state                                 | `./data/ts-db-connector`      | `TS_STATE_DIR`     |
| `hostname`      | Hostname for the Tailscale node (1-63 chars, letters/numbers/hyphens)    | `ts-db-connector`             | `TS_HOSTNAME`      |
| `authkey`       | Tailscale auth key for joining the tailnet                               | *(empty)*                     | `TS_AUTHKEY`       |
| `client_id`     | OAuth/Workload Identity client ID                                        | *(empty)*                     | `TS_CLIENT_ID`     |
| `client_secret` | OAuth client secret                                                      | *(empty)*                     | `TS_CLIENT_SECRET` |
| `id_token`      | Workload Identity ID token                                               | *(empty)*                     | `ID_TOKEN`         |

*Note: At least one authentication method (auth_key, client credentials, or ID token) should be provided unless already connected to the tailnet.*

#### Server Configuration

| Field        | Purpose                                     | Default |
|--------------|---------------------------------------------|---------|
| `admin_port` | HTTP port for admin API and debug endpoints | `8080`  |

#### Database Configuration

Each database is defined in the `databases` object with a unique key. All fields support `env:` and `file:` prefixes to load field value from references.
Sensitive information should always be provided from a secured reference.

| Field            | Purpose                                                    | Default                                           |
|------------------|------------------------------------------------------------|---------------------------------------------------|
| `engine`         | Database type                                              | *(required)*                                      |
| `host`           | Database server hostname or IP                             | `localhost`                                       |
| `port`           | Database server port (0-65535)                             | Engine-specific e.g. Postgres=5432, MongoDB=27017 |
| `listening_port` | Port where connector listens for Tailscale connections     | Same as `port`                                    |
| `ca_file`        | Path to database TLS CA certificate                        | *(required)*                                      |
| `admin_user`     | Database admin user for managing ephemeral credentials     | *(required)*                                      |
| `admin_password` | Database admin password for managing ephemeral credentials | *(required)*                                      |

#### Full Configuration Example

```json
{
  // Comments are allowed in HuJSON format
  "tailscale": {
    "control_url": "https://login.tailscale.com",
    "hostname": "my-db-connector",
    "authkey": "env:TS_AUTHKEY"
  },
  "connector": {
    "admin_port": 8080
  },
  "databases": {
    "production-pg": {
      "engine": "postgres",
      "host": "pg.internal.example.com",
      "port": 5432,
      "ca_file": "./certs/pg-ca.crt",
      "admin_user": "connector_admin",
      "admin_password": "file:/secrets/pg-admin-password"
    },
    "analytics-crdb": {
      "engine": "cockroachdb",
      "host": "crdb.internal.example.com",
      "port": 26257,
      "ca_file": "./certs/crdb-ca.crt",
      "admin_user": "root",
      "admin_password": "env:CRDB_ADMIN_PASSWORD"
    }
  }
}
```

#### Minimal Configuration Example

```json
{
  "databases": {
    "production-pg": {
      "engine": "postgres",
      "ca_file": "./certs/pg-ca.crt",
      "admin_user": "connector_admin",
      "admin_password": "file:/secrets/pg-admin-password"
    }
  }
}
```

## Development

### Useful Make Targets

- `make dev` - Build with debug flags
- `make build` - Build with release settings
- `make containers` - Start test containers for local development
- `make run` - Build and run the connector for local development
- `make test` - Run unit tests
- `make test_acc` - Run unit & acceptance tests

### Setup Instructions

1. (Optional) Start your custom Tailscale control server if not using https://login.tailscale.com/

   ```bash
   ./path/to/local/tailscale/server
   ```

2. Set the `TS_SERVER` environment variable to point to your Tailscale control server for future steps.

   ```bash
   export TS_SERVER=https://login.tailscale.com # http://localhost:31544 for local control
   ```

3. Connect your workstation to a tailnet on your Tailscale control server.

   ```bash
   tailscale up --login-server=$TS_SERVER
   ```

5. Configure the databases capability in your tailnet policy file. The example below works out of the box with
   the test database containers provided for local development. ($TS_SERVER/admin/acls/file)

   ```json
   {
     "tagOwners": {
       "tag:ts-db-connectors": ["autogroup:admin"]
     },
     "grants": [
       {
         "src": ["*"],
         "dst": ["tag:ts-db-connectors"],
         "ip": [
           "tcp:5432",
           "tcp:26257",
           "tcp:27017",
           "tcp:8080",
         ],
         "app": {
           "tailscale.com/cap/databases": [
             {
               "my-postgres-1": {
                 "engine": "postgres",
                 "access": [
                   {
                     "databases": ["testdb"],
                     "roles": ["test"]
                   }
                 ]
               },
               "my-cockroachdb-1": {
                 "engine": "cockroachdb",
                 "access": [
                   {
                     "databases": ["testdb"],
                     "roles": ["test"]
                   }
                 ]
               },
               "my-mongodb-1": {
                 "engine": "mongodb",
                 "access": [
                   {
                     "databases": ["testdb"],
                     "roles": ["test"]
                   }
                 ]
               }
             }
           ]
         }
       }
     ]
   }
   ```

6. Create an authkey so the ts-db-connector can join your tailnet. All databases will be accessible via a single node with hostname "ts-db-connector". ($TS_SERVER/admin/settings/keys)

   ![Alt text](assets/authkey-screenshot-readme.png)

7. Set the `TS_AUTHKEY` environment variable with the authkey you created for future steps.

   ```bash
   export TS_AUTHKEY=tskey-auth-1234 # reusable ephemeral key is recommended for quick iterations
   ```

9. Run docker compose to start pre-configured test database containers. This will set up the databases and update a `data/.config.hujson` config file with the database entries.
   By default, the development ts-db-connector uses that config file.

   ```bash
   # Start all database engines (default)
   make containers

   # Start only specific database engines
   make containers SERVICES="postgres"
   make containers SERVICES="postgres cockroachdb"
   make containers SERVICES="mongodb"
   ```

10. Run the ts-db-connector on your host machine.

    ```bash
    # Use default config file (data/.config.hujson)
    make run

    # Use a custom config file
    make run CONFIG=path/to/your/config.json
    ```

    The connector will join your tailnet and start serving database connections over Tailscale.

11. Connect to the databases over Tailscale, works from anywhere without credentials. All databases are accessible via the ts-db-connector hostname on their respective ports.

    ```bash
    # Connect to Postgres
    psql -h ts-db-connector -p 5432 -U test -d testdb

    # Connect to CockroachDB
    psql -h ts-db-connector -p 26257 -U test -d testdb

    # Connect to MongoDB
    mongosh "mongodb://test:test@ts-db-connector:27017/testdb"
    ```
    
## Testing

By default, the acceptance tests run against [testcontrol](https://github.com/tailscale/tailscale/tree/main/tstest/integration/testcontrol), an in-memory fake control server that we also use to test other parts of Tailscale. 
We're planning to decouple this setup further in the near future so that the same test scenarios can be run against a real tailnet and control server.

The tests use [testcontainers-go](https://golang.testcontainers.org) to create containerised databases instances.
If your container management tool places the Docker socket file in a non-standard location, you need to symlink that location to `/var/run/docker.sock`.
```
sudo ln -s $DOCKER_SOCKET_FILE_LOCATION /var/run/docker.sock
```
Alternatively, if you don't want this to apply globally, set the DOCKER_HOST environment variable to that custom location.

To run the unit & acceptance tests
```
make test_acc
```

To run only the unit tests
```
make test
```
