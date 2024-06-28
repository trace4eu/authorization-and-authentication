import requests
import json
from jwcrypto import jwk, jwt

admin_url = "http://localhost:4445/"
bearer_token="eyJhbGciOiJFUzI1NiIsImtpZCI6IiNrZXkxIiwidHlwIjoiand0In0.eyJhdWQiOiJhdXRob3JpemF0aW9uLWFuZC1hdXRoZW50aWNhdGlvbi1jb21wb25lbnQiLCJpc3MiOiJhdXRob3JpemF0aW9uLWFuZC1hdXRoZW50aWNhdGlvbi1jb21wb25lbnQiLCJzdWIiOiJ0ZXN0LXNjcmlwdCJ9.4UMJMqSh42eAmRPSgfe8IBo6XPODrEcfo0Kgo66EaJja_G8_qbhDR3cwky8ZP9TV7y0MQ3fCsX528dds8kgoqQ"


'''
The following code creates and stores Hydra a new client
key.
'''
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
    'Authorization': 'Bearer ' + bearer_token
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