import http.client
import json
def send(url, message):
    host = url.split("//")[1]
    conn = http.client.HTTPSConnection(host)
    headers = {
        'Content-type': 'application/json'
    }
    json_data = json.dumps({
        "message": message
    })
    conn.request("POST", "/send_message", json_data, headers)
    response = conn.getresponse()
    print(response.read().decode())