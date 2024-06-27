<img src="https://trace4eu.eu/wp-content/uploads/2023/09/Logo_TRACE4EU_horizontal_positive_RGB.png" width="250" alt="TRACE4EU Logo">

# authorization-and-authentication

This is an initial demo version of the TRACE4EU authorization-and-authentication service, currently based on [Ory](https://www.ory.sh/).

This is part of TRACE4EU T2.2:

* https://nextcloud.trace4eu.eu/apps/files/files/29886?dir=/TRACE4EU/WP2%20Technology%2C%20interoperability%20and%20cybersecurity/T22

**Warning:** This is a demo component, NOT ready for production! Secrets are currently hardcoded inside this repo. Use at your own risk!

This component uses:
* [Ory hydra](https://www.ory.sh/hydra/)
* [Ory oathkeeper](https://www.ory.sh/docs/oathkeeper)

# Run
From the compose directory execute:

```bash
docker-compose -f authorization-and-authentication.yml up --build
```

# Build

```bash
docker build -f ./docker/Dockerfile . -t trace4eu/authorization-and-authentication
```

# Run

```bash
docker run -it -p 4444:4444 -p 4445:4445 trace4eu/authorization-and-authentication
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
# JWTs for client authentication

A client can be configured to use JWT for authentication. An example of suitable
JSON Web key follows (note that it includes the private part as well)

```
{
    "crv":"P-256",
    "d":"TvKuAqV1y1pTlWhJ_BG9WZZvnu1n0bonuleoZDtT89k",
    "kty":"EC","x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E",
    "kid":"test-client-jwt-jwk#1",
    "use":"sig"
}
```

A client that supports
this type of authentication can be added by invoking the `clients` admin endpoint
with the following payload.

```
{
    "client_id": "test-client-jwt",
    "grant_types": [
        "client_credentials"
    ],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks": {
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "kid": "test-client-jwt-jwk#1",
                "crv": "P-256",
                "x": "3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
                "y": "gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E"
            }
        ]
    },
    "scope": "entity_creation signature_endpoint update_credential"
}
```
The `create_user.py` script located in folder `scripts` includes a python script
for creating such a client.

A token can be requested by generating an appropriate `assertion`. The 
specifications of such an assertion are defined [here](https://www.ory.sh/docs/hydra/guides/jwt#jwts-for-client-authentication).
Then, a request to the token endpoint is made using the following parameters:

```
"grant_type":"client_credentials",
"client_id":the client id,
"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
"client_assertion":the assertion
```
The `get_token.py` script located in folder `scripts` includes a python script
for requesting a token.
