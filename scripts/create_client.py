import requests
import json
from jwcrypto import jwk, jwt

admin_url = "http://localhost:4445/"

#------Prepare JWK--------------

json_key = json.dumps({
    "crv":"P-256",
    "d":"TvKuAqV1y1pTlWhJ_BG9WZZvnu1n0bonuleoZDtT89k",
    "kty":"EC","x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E",
    "kid":"test-client-jwt-jwk#1",
    "use":"sig"
})

jwk_key = jwk.JWK.from_json(json_key)


#------Add Client-------------------
headers = {
        'Content-Type': 'application/json',
        }

payload = {
            "client_id": "test-client-jwt" ,
            "grant_types": [
                "client_credentials"
            ],
            "token_endpoint_auth_method":"private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks":{"keys":
                [jwk_key.export_public(as_dict=True)]
                }
                ,
            "scope":"entity_creation signature_endpoint update_credential"
        }

response = requests.request("POST", admin_url + "clients", headers=headers, data=json.dumps(payload))
print(response.text)