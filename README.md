# watchdog-keycloak

Validate Keycloak server settings against a YAML file describing what it should
have.

# Compile
```
mvn clean install
```

# Run
```
java -jar target/watchdog-keycloak.jar \
    --config=config.yaml \
    --password=super_secret
```

If there are validation failures, the exit code will be non-zero and the error
message is printed out.

# Config file
The config file should be in this format:
```yaml

keycloak:
  server: https://localhost:8080/auth
  realm: real-realm
  user: sunshine
  client: test

watchdog:
  - name: pnc admins
    users:
      - dcheung
    allowedRoles:
      - user
      - admin
    deniedRoles:
      - "realm-management:manage-*"
      - user

watchdogDefault:
  allowedRoles:
    - user
  deniedRoles:
    - "realm-management:mange-*"

defaultRoles:
  - user
```
The `keycloak` section defines which Keycloak server, and realm to talk to. The user used needs to have those 2 client
roles:
- realm-management:view-users
- realm-management:view-clients

The `watchdog` section defines a list of profiles of users. For each profile,
a list of users need to have approved roles, and other roles they shouldn't be
in.

The `watchdogDefault` section defines the approved an denied roles that the
users not defined in a profiles, should obey.

The `defaultRoles` section defines the list of roles that should be added
by default to users.

