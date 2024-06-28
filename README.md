<img src="https://trace4eu.eu/wp-content/uploads/2023/09/Logo_TRACE4EU_horizontal_positive_RGB.png" width="250" alt="TRACE4EU Logo">

# authorization-and-authentication

This is an initial demo version of the TRACE4EU authorization-and-authentication service, currently based on [Ory](https://www.ory.sh/).

This is part of TRACE4EU T2.2:

* https://nextcloud.trace4eu.eu/apps/files/files/29886?dir=/TRACE4EU/WP2%20Technology%2C%20interoperability%20and%20cybersecurity/T22

**Warning:** This is a demo component, NOT ready for production! Secrets are currently hardcoded inside this repo. Use at your own risk!

This component uses:
* [Ory hydra](https://www.ory.sh/hydra/)
* [Ory oathkeeper](https://www.ory.sh/docs/oathkeeper)

# Component modules
![Authorization and authentication component modules](images/auth-and-authz-topology.png)

Oauth2.0 functionality of this component is handled by Ory hydra. Hydra's admin API
is protected using oathkeeper and [JWT authenticator](https://www.ory.sh/docs/oathkeeper/pipeline/authn#jwt).
Particularly, authorized API clients should include a JWT in the HTTP Authorization header of their requests
JWTs should be signed using a key included in oathkeeper's configuration folder.

The provided code includes an example of a JWT signing key, as well as an example of a script
configured with an appropriate Bearer token. It also includes a script, named `generate_api_jwt.py`
for generating a new key and a new Bearer token. 

# Run
From the compose directory execute:

```bash
docker-compose -f authorization-and-authentication.yml up --build
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
The `config.py` script located in folder `scripts` includes a python script
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
The `client.py` script located in folder `scripts` includes a python script
for requesting a token.
