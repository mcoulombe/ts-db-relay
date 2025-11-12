# ts-db-connector

A [tsnet](https://tailscale.com/kb/1244/tsnet) application letting Tailscale nodes access databases from anywhere using their Tailscale identity to authenticate.

## Local setup

1. Build the binary.

   ```bash
   go build -gcflags="all=-N -l" -o ./cmd/ts-db-connector ./...
   ```

2. (Optional) Start your custom Tailscale control server if not using https://login.tailscale.com/

   ```bash
   ./path/to/local/tailscale/server
   ```

3. Set the `TS_SERVER` environment variable to point to your Tailscale control server for future steps.

   ```bash
   export TS_SERVER=https://login.tailscale.com # http://localhost:31544 for local control
   ```

4. Connect your workstation to a tailnet on your Tailscale control server.

   ```bash
   tailscale up --login-server=$TS_SERVER
   ```

5. Configure the databases capability in your tailnet policy file. ($TS_SERVER/admin/acls/file)

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
           "tcp:80",
           "tcp:26257",
           "tcp:81"
         ],
         "app": {
           "tailscale.test/cap/databases": [
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
   export TS_AUTHKEY=tskey-auth-x-x # reusable ephemeral key is recommended for quick iterations
   ```

9. Run docker compose to start pre-configured test databases. This will set up the databases and update the `data/.config.hujson` file with the database entries.

   ```bash
   # Start all database engines (default)
   docker compose -f test-setup/compose.yml up --build

   # Start only specific database engines (include 'setup' to create config file)
   docker compose -f test-setup/compose.yml up --build setup postgres
   docker compose -f test-setup/compose.yml up --build setup postgres cockroachdb
   docker compose -f test-setup/compose.yml up --build setup mongodb
   ```

   Available services: `setup`, `postgres`, `cockroachdb`, `mongodb`

   The setup scripts will populate `data/.config.hujson` with database connection details.

10. Run the ts-db-connector on your host machine.

    ```bash
    TS_AUTHKEY=$TS_AUTHKEY ./cmd/ts-db-connector --config=data/.config.hujson
    ```

    The connector will join your tailnet and start serving database connections over Tailscale.

11. Connect to the databases over Tailscale, works from anywhere without credentials. All databases are accessible via the ts-db-connector hostname on their respective ports.

    ```bash
    # Connect to Postgres
    psql -h ts-db-connector -p 5432 -U test -d testdb

    # Connect to CockroachDB
    psql -h ts-db-connector -p 26257 -U test -d testdb

    # Connect to MongoDB
    mongosh "mongodb://test@ts-db-connector:27017/testdb"
    ```