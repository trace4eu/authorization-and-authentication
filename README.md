<img src="https://trace4eu.eu/wp-content/uploads/2023/09/Logo_TRACE4EU_horizontal_positive_RGB.png" width="250" alt="TRACE4EU Logo">

# authorization-and-authentication

This is an initial demo version of the TRACE4EU authorization-and-authentication service, currently based on [Ory](https://www.ory.sh/).

This is part of TRACE4EU T2.2:

* https://nextcloud.trace4eu.eu/apps/files/files/29886?dir=/TRACE4EU/WP2%20Technology%2C%20interoperability%20and%20cybersecurity/T22

**Warning:** This is a demo component, NOT ready for production! Use at your own risk!

# Build

```bash
docker build -f ./docker/Dockerfile . -t trace4eu/authorization-and-authentication
```

# Run

```bash
docker run -it -p 4444:4444 trace4eu/authorization-and-authentication
```

# Demo OAuth2 client credentials

| client_id                             | client_secret    |
|---------------------------------------|------------------|
| 30ad6340-8706-47d1-baef-868208334609  | phae-Vei5phi1xu8 |
| c85a016e-9c4a-4978-b110-d12902217992  | riezahd-o4IZue8u |
| dbf2c28a-bfc0-4a89-b304-0319b48ff438  | ohM-ei1ieheimeiz |

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
  "http://localhost:4445/oauth2/introspect"
```
