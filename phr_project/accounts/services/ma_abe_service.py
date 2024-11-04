import hashlib
from typing import List, Mapping

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

from accounts.utils.charm_helpers import CharmMAABEHelper


class MAABEService:
    def __init__(self):
        self.helper = CharmMAABEHelper()
        self.group = self.helper.get_pairing_group()

    def encrypt(self, file, policy):
        key = self.helper.get_random_group_element()
        # encrypt the AES key with the policy
        abe_policy_enc_key = self.helper.encrypt(key, policy)
        # print(f"AES KEY Encrypted with ABE key and policy: {abe_policy_enc_key}")

        # instantiate a symmetric enc scheme from this key
        serialized_key = self.helper.get_pairing_group().serialize(key)
        cipher = SymmetricCryptoAbstraction(hashlib.sha256(serialized_key).digest())
        sym_enc_file = cipher.encrypt(file)
        return {'abe_policy_enc_key': abe_policy_enc_key, 'sym_enc_file': sym_enc_file}

    def decrypt(self, user_keys, enc_file):
        abe_enc_session_key = enc_file['abe_policy_enc_key']
        key = self.helper.decrypt(user_keys, abe_enc_session_key)
        print(f"Decrypted AES key: {key}")
        sym_enc_file = enc_file['sym_enc_file']
        print(f"Symmetrically encrypted file: {sym_enc_file}")
        serialized_key = self.helper.get_pairing_group().serialize(key)
        cipher = SymmetricCryptoAbstraction(hashlib.sha256(serialized_key).digest())
        return cipher.decrypt(sym_enc_file)
