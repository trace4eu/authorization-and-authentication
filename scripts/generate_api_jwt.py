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
    "crv":"P-256",
    "d":"TvKuAqV1y1pTlWhJ_BG9WZZvnu1n0bonuleoZDtT89k",
    "kty":"EC","x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E"
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
