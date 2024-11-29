import requests
import json
import uuid
import time
from jwcrypto import jwk, jwt

token_url = "http://localhost:4444/oauth2/token"

#------Prepare JWK--------------

json_key = json.dumps({
    "crv":"P-256",
    "d":"TvKuAqV1y1pTlWhJ_BG9WZZvnu1n0bonuleoZDtT89k",
    "kty":"EC",
    "x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E",
    "kid":"authorized-user-1#1",
    "use":"sig"
})

jwk_key = jwk.JWK.from_json(json_key)

#------Step 3: User, client authorization-------------------
jwt_header = {
            "typ": "jwt",
            "alg": "ES256",
            "kid":"authorized-user-1#1",
        }

jwt_claims={
    "iss":"authorized-user-2",
    "sub":"authorized-user-2",
    "aud": token_url,
    "iat": int(time.time()),
    "jti":str(uuid.uuid4()),
    "exp": int(time.time()) + 600 #expire in 10 minutes
}

authorization = jwt.JWT(header=jwt_header, claims=jwt_claims)
authorization.make_signed_token( jwk_key)

print(authorization.serialize())
