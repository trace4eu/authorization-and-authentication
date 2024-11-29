import requests
import json
from jwcrypto import jwk, jwt

admin_url = "http://localhost:4445/"
bearer_token="<admin-bearer-token>"



#------Prepare JWK--------------

json_key = json.dumps({
    "crv":"P-256",
    "kty":"EC",
    "x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E",
    "kid":"authorized-user-1#1",
    "use":"sig"
})

jwk_key = jwk.JWK.from_json(json_key)

#------Step 1: Register User public key-------------------
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + bearer_token
}

payload = {
    "expires_at": "2025-08-24T14:15:22Z",
    "issuer": "authorized-user-1",
    "subject":"test-client-1",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwk": jwk_key.export_public(as_dict=True),
    "scope": [
        "http://trace4.eu/ocs/item1,read",
        "http://trace4.eu/ocs/item1,write",
        "http://trace4.eu/ocs/item3,read"
    ],
}


response = requests.request("POST", admin_url + "trust/grants/jwt-bearer/issuers", headers=headers, data=json.dumps(payload))
print(response.text)
