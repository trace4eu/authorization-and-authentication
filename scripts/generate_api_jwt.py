from jwcrypto import jwk, jwt
import json

'''
This key has been generated using the following commands
key = jwk.JWK.generate(kty='EC', crv='P-256')
key.export()

This key will be used to sign JWTs. The key is copied to
jwks.json file which should be copied in the folder ../compose/config/oathkeeper

Note that this object includes the private key as well
'''

json_key = json.dumps({
    "kid":"#key1",
    "use":"sig",
    "crv":"P-256",
    "d":"...",
    "kty":"EC",
    "x":"...",
    "y":"...."
})

jwk_signin_key = jwk.JWK.from_json(json_key)

# Generate jwks.json
jwks = {
    'keys':[]
}

jwks['keys'].append(jwk_signin_key.export_public(as_dict=True))

with open('jwks.json', 'w') as jwks_json:
    jwks_json.write(json.dumps(jwks))

print("Copy 'jwks.json' in '../compose/config/oathkeeper'")

# Generate bearer token
#------Token request-------------------
jwt_header = {
    "typ": "jwt",
    "alg": "ES256",
    "kid":"#key1"
}

jwt_claims={
    "iss":"authorization-and-authentication-component",
    "sub":"test-script",
    "aud":"authorization-and-authentication-component"
}

signed_jwt = jwt.JWT(header=jwt_header, claims=jwt_claims)
signed_jwt.make_signed_token(jwk_signin_key)

print("Bearer token:",signed_jwt.serialize(compact=True))
