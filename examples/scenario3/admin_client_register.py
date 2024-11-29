import requests
import json


admin_url = "http://localhost:4445/"
bearer_token="<admin-bearer-token>"


#------Step2: Admin, client registration-------------------
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + bearer_token
}

payload = {
    "client_id": "test-client-1-jwt",
    "client_secret":"aclientsecret",
    "grant_types": [
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ],
    "access_token_strategy":"jwt"
}

response = requests.request("POST", admin_url + "clients", headers=headers, data=json.dumps(payload))
print(response.text)
