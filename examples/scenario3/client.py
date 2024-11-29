import requests
import base64


token_url = "http://localhost:4444/oauth2/token"
client_id =  "test-client-1-jwt"
client_secret = "aclientsecret"

#Replace the following grant with the output of the user.py script
authorization_grant= "eyJhbGciOiJFUzI1NiIsImtpZCI6ImF1dGhvcml6ZWQtdXNlci0xIzEiLCJ0eXAiOiJqd3QifQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjQ0NDQvb2F1dGgyL3Rva2VuIiwiZXhwIjoxNzIyNDE4MDY1LCJpYXQiOjE3MjI0MTc0NjUsImlzcyI6ImF1dGhvcml6ZWQtdXNlci0yIiwianRpIjoiODk5ODI5OGYtZGM1YS00NGQzLTllMDctYjM0YzY1MGQxM2ZkIiwic3ViIjoiYXV0aG9yaXplZC11c2VyLTIifQ.IWvhsBWZg7i91pSvhAcucsCAIV3Z_eiMZiDzwbrU1pq9DKvCQ40MK4R01Gaf2k0L_S2nl8nI35gV1hv8bgs_9A"

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