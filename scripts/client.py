import requests
import json
import uuid
import time
from jwcrypto import jwk, jwt

'''
An OAuth 2.0 client application that receives a token from Hydra
using client credentials grant type and a JWT assertion.
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

#------Token request-------------------
jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "kid":"test-client-jwt-jwk#1"
        }

jwt_claims={
    "iss":"test-client-jwt",
    "sub":"test-client-jwt",
    "aud":"https://auth.trace4eu.eu/oauth2/token",
    "jti":str(uuid.uuid4()),
    "exp": int(time.time()) + 600 #expire in 10 minutes
}

assertion = jwt.JWT(header=jwt_header, claims=jwt_claims)
assertion.make_signed_token( jwk_key)


# Generate access token request
payload={
    "grant_type":"client_credentials",
    "client_id":"test-client-jwt",
    "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion":assertion.serialize()
}

headers={
    "Content-Type":"application/x-www-form-urlencoded"
}

token_url = "http://localhost:4444/oauth2/token"

response = requests.post(token_url, headers = headers, data = payload)

print(response.text)