import os

class KeyManager:

    def issueNewKey(self, policy: str) -> str:
        """
        Generates a new AES key and encrypts it with the given policy.

        Args:
            (str) policy: The policy for the AES key
        
        Returns:
            (str) The unencrypted AES key.
        """
        if self.__msk == "":
            raise ValueError("[ERR][KeyManager] Cannot issue keys without a Master Secret Key from authority.")
        
        pass

    def getKey(self, identifier: str) -> str:
        """
        Returns the desired key (if it exists).

        Args:
            (str) identifier: The key identifier (e.g. msk)
        
        Returns:
            (str) The corresponding key
        """

    def addNewKey(self, identifier: str, key) -> None:
        """
        Adds a new key to the manager.

        Args:
            (str) identifier: The key identifier (e.g. msk)
            (str) key: The actual key
        """
        if identifier == "msk" and self.__msk != "":
            raise ValueError("[ERR][KeyManager] Attempt to override Master Secret Key.")
        if identifier in self.__keys.keys():
            raise ValueError("[ERR][KeyManager] Attempt to override existing key.")
        
        if identifier == "msk":
            self.__msk = key
        else:
            self.__keys[identifier] = key

        self.__saveKey(identifier, key)

    def hasKeys(self):
        return len(self.__keys.keys()) > 0

    def __init__(self, base_path: str = "keys/"):
        """
        Stores the base path of where encrypted keys will be stored.

        Args:
            (str) base_path: The folder containing the key files
        """
        self.__base_path = base_path
        self.__keys = {}
        self.__msk = ""

        if len(os.listdir(self.base_path)) == 0:
            print(f"[WRN][KeyManager] No keys found at given location: {self.__base_path}")
        else:
            self.__loadKeys()

    def __loadKeys(self):
        """
        Loops through all the files, and loads the encrypted keys.
        """
        for filePath in os.listdir(self.__base_path):
            with open(filePath, "r") as file:
                # TODO: Read key type and encrypted key from file
                pass

    def __saveKey(self, identifier: str, key):
        """
        Saves the key to a file.

        Args:
            (str) identifier: The key identifier (e.g. msk)
            (str) key: The actual key
        """
        pass