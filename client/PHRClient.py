from HttpClient import HttpClient
from KeyManager import KeyManager

class PHRClient:

    def __init__(self):
        """
        Initializes the HttpClient and the KeyManager.
        """
        self.httpClient = HttpClient()
        self.keyManager = KeyManager()

        # Perform checks to determine the state of the client
        if self.keyManager.msk == "":
            # No previous communication with the server.
            # Hence request new keys.
            user_type = input("Please specify if you're a: \
                                    1) Patient             \
                                    2) Doctor              \
                                    3) Insurance Provider \
                                    4) Employer     \
                                    5) Health Club Owner    \
                              ")
            assert int(user_type) < 6 and int(user_type) > 0

            keyJSON = self.httpClient.GET(f'user_setup/{user_type}')
            self.keyManager.addNewKey("msk", keyJSON)
        
        if not self.keyManager.hasKeys():
            # Did not find / no session keys have been generated.
            # TODO: Generate AES keys for each policy