import requests
import base64


token_url = "http://localhost:4444/oauth2/token"
client_id =  "test-client-1"
client_secret = "aclientsecret"

#Replace the following grant with the output of the user.py script
authorization_grant= "eyJhbGciOiJFUzI1NiIsImtpZCI6ImF1dGhvcml6ZWQtdXNlci0xIzEiLCJ0eXAiOiJqd3QifQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjQ0NDQvb2F1dGgyL3Rva2VuIiwiZXhwIjoxNzIxODQyMTA2LCJpYXQiOjE3MjE4NDE1MDYsImlzcyI6ImF1dGhvcml6ZWQtdXNlci0xIiwianRpIjoiZGZjOTNmODEtN2JmMy00NjI3LTg4MTctZDAwZThmYjgzZDZmIiwic2NwIjpbImh0dHA6Ly90cmFjZTQuZXUvb2NzL2l0ZW0xLHJlYWQiXSwic3ViIjoidGVzdC1jbGllbnQtMSJ9.Cbp4d8LwuwR1DqiLSZHsNnZx2IXY_smm8kc1IcuxPXet56qv2vbnbdUqXLnD6d0YD6KV8jSMS_RHeiNWVzSQtA"

#------Step 4: Client, access token request-------------------

# Generate access token request
payload={
    "grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion":authorization_grant,
    "scope":"http://trace4.eu/ocs/item1,read http://trace4.eu/ocs/item1,write"
}
authorization_header = client_id + ":" + client_secret
headers={
    "Content-Type":"application/x-www-form-urlencoded",
    "Authorization": "Basic " + base64.b64encode(authorization_header.encode()).decode()
}


response = requests.post(token_url, headers = headers, data = payload)

print(response.text)