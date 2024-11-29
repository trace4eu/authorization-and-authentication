import requests
import json
import uuid
import time
from jwcrypto import jwk, jwt

token_url = "https://api-dev-auth.trace4eu.eu/oauth2/token"
client_id = "..."
kid = "..."

'''
An OAuth 2.0 client application that receives a token from Hydra
using client credentials grant type and a JWT assertion.
'''

#------Prepare JWK--------------

json_key = json.dumps({
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "...",
                        "y": "...",
                        "d": "...",
                        "kid":kid,
                      })


jwk_key = jwk.JWK.from_json(json_key)

#------Step 3: Client, access token request-------------------
jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "kid": kid
        }

jwt_claims={
    "iss":client_id,
    "sub":client_id,
    "aud": token_url,
    "jti":str(uuid.uuid4()),
    "exp": int(time.time()) + 600 #expire in 10 minutes
}

assertion = jwt.JWT(header=jwt_header, claims=jwt_claims)
assertion.make_signed_token( jwk_key)


# Generate access token request
payload={
    "grant_type":"client_credentials",
    "client_id":client_id,
    "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion":assertion.serialize(),
    "scope":"ocs:read ocs:write qtsp:timestamp"
}

headers={
    "Content-Type":"application/x-www-form-urlencoded"
}



response = requests.post(token_url, headers = headers, data = payload)

print(response.text)
