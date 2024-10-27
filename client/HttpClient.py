import requests
from typing import Any

# Client key management
# ---
# GET (UUID, user keys) from server     <- API ENDPOINT 1 : Supports only a GET
# 
# Generate 1 AES key / policy
# Encrypts AES key with policy
#   -> Send ENC_AES to the server       <- API ENDPOINT 2 : Supports a PUT / POST : Update user key
#                                                                      GET : Sends the ENC_AES
#
#   -> keep local copy of user key
#   -> keep local copy of AES key
#
# Retrieve the PHR                      <- API ENDPOINT 3 : Supports a GET : Returns the PHR (encrypted)
#                                                                      POST : Updates the PHR
#                                                               <- Challenge
#                                                               -> Response
#

# TODO: Generate AES keys
# TODO: Encrypt AES keys with the policy -> pull ma-abe
# TODO: Save these to file (and load)
# TODO: Endpoint communication.


# Let UUID = 1
# ---
#
# (Patient@PHR_[UUID] || Doctor@Hospital_[UUID]) -> main record
# (Patient@PHR_[UUID] || Doctor@Hospital_[UUID] || Provider@HealthClub_[UUID] ) -> health club data
# (Patient@PHR_[UUID] || Employer@Employer_[UUID])
#


class HttpClient:
    server: str = "localhost"
    port: str = "8000"

    def GET(self, api_endpoint: str) -> dict:
        """
        Makes a GET request to an API endpoint

        Args:
            (str) api_endpoint: The URI of the endpoint.

        Returns:
            (Dict) JSON representation of response payload
        """
        return self.__connect_to_host(api_endpoint, 'GET')

    def POST(self, api_endpoint: str, payload: Any) -> dict:
        """
        Sends a POST request to an API endpoint

        Args:
            (str) api_endpoint: The URI of the endpoint.
            (any) payload: The payload data of the request

        Returns:
            (Dict) JSON representation of response payload
        """
        return self.__connect_to_host(api_endpoint, 'POST', payload)

    def __init__(self, server: str = None, port: str = None):
        """
        Upon initialization, every client will generate the base URL
        of the target website. By default, the client will use the class's
        (server, port) for resolution.

        Args:
            (str) server: The server name (e.g. google.com)
            (str) port: custom port (if none provided, defaults to 80)
        """
        if server and port:
            self.__baseURL = f"{server}:{port}/"
        elif server:
            self.__baseURL = f"{server}/"        
        else:
            self.__baseURL = f"{HttpClient.server}:{HttpClient.port}/"


    def __connect_to_host(self, api_endpoint: str, method: str, payload: Any = None) -> dict:
        """
        Makes a generic request to an API endpoint
        
        This function sends a request to an URL and returns the JSON of the response
        payload. The only supported methods are GET and POST.

        Args:
            (str) api_endpoint: The URI of the endpoint.
            (str) method: The method of the request. Can be GET or POST.
            (any) payload: The payload data of the request

        Returns:
            (Dict) JSON representation of response payload
        """
        if method == 'GET':
            resp = requests.get(self.__baseURL + api_endpoint)

            return resp.json()
        
        elif method == 'POST':
            resp = requests.post(self.__baseURL + api_endpoint, payload)

            return resp.json()