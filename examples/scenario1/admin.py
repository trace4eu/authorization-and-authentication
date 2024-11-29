import requests
import json
from jwcrypto import jwk, jwt

admin_url = "https://api-dev-admin-auth.trace4eu.eu/"
bearer_token="<admin-bearer-token>"

client_id = "did:ebsi:z..."


#------Prepare JWK--------------

json_key = json.dumps({
                        "use": "sig",
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "...",
                        "y": "...",
                        "d": "...",
                        "kid":"...",
                      })


jwk_key = jwk.JWK.from_json(json_key)

#------Step 1: Add Client-------------------
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + bearer_token
}

payload = {
    "client_id": client_id ,
    "grant_types": [
        "client_credentials"
    ],
    "token_endpoint_auth_method":"private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks":{"keys":
        [jwk_key.export_public(as_dict=True)]
        }
}

response = requests.request("POST", admin_url + "clients", headers=headers, data=json.dumps(payload))
print(response.text)

#------Step 2: Configure scope-------------------
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + bearer_token
}

payload = [
    {
    "op": "replace",
    "path": "/scope",
    "value": "ocs:read ocs:write qtsp:timestamp"
    }
]

response = requests.request("PATCH", admin_url + "clients/" + client_id, headers=headers, data=json.dumps(payload))
print(response.text)
