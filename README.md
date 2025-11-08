# ts-db-connector

A [tsnet](https://tailscale.com/kb/1244/tsnet) application letting Tailscale nodes access databases from anywhere using their Tailscale identity to authenticate.

## Local setup

1. Build the binary.

   ```bash
   GOOS=linux GOARCH=amd64 go build -o ./cmd/ts-db-connector.exe ./...
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
               }
             }
           ]
         }
       }
     ]
   }
   ```

6. Create an authkey so the ts-db-connector node can join your tailnet. ($TS_SERVER/admin/settings/keys)

   ![Alt text](assets/authkey-screenshot-readme.png)

7. Set the `TS_AUTHKEY` environment variable with the authkey you created for future steps.

   ```bash
   export TS_AUTHKEY=tskey-auth-x-x # reusable ephemeral key is recommended for quick iterations
   ```

8. (Optional) If using a custom local control server, update the `TS_SERVER` environment variable for container access.

   ```bash
   export TS_SERVER=http://host.docker.internal:31544
   ```

9. Run docker compose to start a container with your local ts-db-connector binary and pre-configured test databases.

   ```bash
   docker compose -f test-setup/compose.yml up --build
   ```

10. Connect to the database over Tailscale, works from anywhere without credentials.

    ```bash
    psql -h postgres-db -p 5432 -U test -d testdb
    ```