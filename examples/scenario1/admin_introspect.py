import requests
import json
from jwcrypto import jwk, jwt

'''
This the the access token received from a client using step 3
'''
access_token = "ory_at_8XhShW82-ZUQmMLtTqjNdzXuL38SvUj24RN8HIxSB3g.5wVAHgezzwDTqhPH2SbPGLPrrFraOMYvWv_6maJjLGQ"

admin_url = "http://localhost:4445/"
bearer_token="<admin-bearer-token>"



#------Prepare JWK--------------

json_key = json.dumps({
    "crv":"P-256",
    "kty":"EC",
    "x":"3qmoY1Bs0eJ319TLku5ofe7q2guicdFSIu22miBLXHY",
    "y":"gRzDzzvTGuyJp7ypFWuboC21KhsxpcpQMo9IcXSt23E",
    "kid":"test-client-jwt-jwk#1",
    "use":"sig"
})

jwk_key = jwk.JWK.from_json(json_key)

#------Step 4: Token introspection-------------------
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Bearer ' + bearer_token
}

payload = {
    "token": access_token
}


response = requests.request("POST", admin_url + "oauth2/introspect", headers=headers, data=payload)
print(response.text)
