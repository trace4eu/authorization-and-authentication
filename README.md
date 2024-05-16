# authorization-and-authentication

This is an initial demo version of the TRACE4EU authorization-and-authentication service, based on [Ory](https://www.ory.sh/).

Warning: This is a demo component, NOT ready for production! Use at your own risk!

# Build

```bash
docker build -f ./docker/Dockerfile . -t trace4eu/authorization-and-authentication
```

# Run

```bash
docker run -it -p 4444:4444 trace4eu/authorization-and-authentication
```

# Request an OAuth2 access token using the client credentials flow (public)

```bash
curl -X POST \
  -H "Authorization: Basic MzBhZDYzNDAtODcwNi00N2QxLWJhZWYtODY4MjA4MzM0NjA5OnBoYWUtVmVpNXBoaTF4dTg=" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data grant_type=client_credentials \
  --data scope=signature_endpoint \
  "http://localhost:4444/oauth2/token"
```

Supported OAuth2 scopes: `entity_creation`, `signature_endpoint`, `update_credential`

Supported OAuth2 clients: see `./docker/run.sh`

# Introspect an OAuth2 access token (admin)

```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data token=.... \
  "http://localhost:4444/oauth2/introspect"
```
