import requests

def connect_to_host(api_endpoint):
    URL = "http://localhost:8000/" + api_endpoint

    r = requests.get(URL)

    print(r.json())


connect_to_host('api/v1/user/1')
