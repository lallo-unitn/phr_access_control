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

    def test(self):
        from accounts.services.user_service import test_get_user_secret_key
        ########## Example Usage ##########
        ma_abe_service = self
        id_bob = "0"

        user_auth_attrs: Mapping[str, List] = {}

        # DO NOT PUT IDS HERE !!!
        user_attrs = ['PATIENT@PHR', 'DOCTOR@PHR']

        # # iterate on the user attributes
        for user_attr in user_attrs:
            attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
            if attr_auth not in user_auth_attrs:
                user_auth_attrs[attr_auth] = []
            user_auth_attrs[attr_auth].append(user_attr)
            print(f"user_auth_attrs: {user_auth_attrs}")

        # #
        user_keys_by_auth: Mapping[str, List] = {}
        # #
        for auth, user_attrs in user_auth_attrs.items():
            user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(auth, id_bob, user_attrs)
        #
        if len(user_keys_by_auth.keys()) >= 2:
            user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
            print(f"%%%%%%%%%%%user_keys: {user_keys}")
        else:
            temp_user_keys = list(user_keys_by_auth.values())
            user_keys = temp_user_keys.pop()
            print(f"-------------user_keys: {user_keys}")

        # #
        # # user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
        # #
        # user_keys = ma_abe_service.helper.gen_user_key('PHR', id_bob, user_attrs)

        user_keys_bob = {'GID': id_bob, 'keys': user_keys}

        user_keys_bob = test_get_user_secret_key(None, id_bob)

        # id_alice = "alice"
        # usr_attrs_employer = ['PATIENT@PHR_2']
        # usr_attrs_phr = ['PATIENT@PHR_1']
        # usr_attrs_insurance = ['INSURANCEREP@INSURANCE1']
        # user_keys_insurance = ma_abe_service.helper.gen_user_key('INSURANCE1', id_alice, usr_attrs_insurance)
        # user_keys_phr_2 = ma_abe_service.helper.gen_user_key('PHR', id_alice, usr_attrs_phr)

        # user_keys_alice = {'GID': id_alice, 'keys': merge_dicts(user_keys_phr_2, user_keys_insurance)}

        # String message to encrypt
        message = "This is a secret message"

        policy = '(PATIENT@PHR_0)'

        enc_message = ma_abe_service.encrypt(message, policy)

        print(f"Encrypted file before serial/deserial: {enc_message}")

        # abe_policy_enc_key = enc_message['abe_policy_enc_key']
        # sym_enc_file = enc_message['sym_enc_file']

        # Serialize the encrypted AES key
        # serial_abe_policy_enc_key = serialize_encrypted_aes_key(abe_policy_enc_key, ma_abe_service.group)
        # serialize encrypted file to JSON
        # serial_enc_file = serialize_encrypted_data(sym_enc_file)

        # print the serialized data
        # print(f"Serialized Encrypted file: {serial_enc_file}")
        # print(f"Serialized Encrypted AES key: {serial_abe_policy_enc_key}")

        # encoded_aes_key = b64.b64encode(serial_abe_policy_enc_key).decode('utf-8')

        # Step 3: Create JSON payload
        # aes_json = json.dumps({"c_serial": encoded_aes_key})
        # print(aes_json)

        # decoded_aes_key = b64.b64decode(encoded_aes_key)

        # print(f"Decoded AES key: {decoded_aes_key}")

        # deserialize the encrypted AES key
        # deserialized_abe_policy_enc_key = deserialize_encrypted_aes_key(decoded_aes_key, ma_abe_service.group)
        # deserialize symmetrically encrypted file
        # deserialized_enc_file = deserialize_encrypted_data(serial_enc_file)

        # enc_message = {'abe_policy_enc_key': deserialized_abe_policy_enc_key, 'sym_enc_file': deserialized_enc_file}

        # print(f"Encrypted file after serial/deserial: {enc_message}")

        decrypted_message = ma_abe_service.decrypt(user_keys_bob, enc_message)

        print(f"Decrypted file: {decrypted_message}")

# if __name__ == "__main__":

    # ma_abe_service = MAABEService()
    # ma_abe_service.test()