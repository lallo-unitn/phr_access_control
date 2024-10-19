import hashlib
import pickle

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.schemes.abenc.abenc_maabe_rw15 import merge_dicts
from ma_abe.migrations.utils.charm_helpers import CharmMAABEHelper
from ma_abe.migrations.utils.serial import serialize_encrypted_aes_key, to_json, deserialize_encrypted_aes_key, \
    serialize_encrypted_data, deserialize_encrypted_data


class MAABEService:
    def __init__(self):
        self.helper = CharmMAABEHelper()
        self.group = self.helper.get_pairing_group()

    def encrypt(self, file, policy):
        key = self.helper.get_random_group_element()
        #encrypt the AES key with the policy
        abe_policy_enc_key = self.helper.encrypt(key, policy)
        print(f"AES KEY Encrypted with ABE key and policy: {abe_policy_enc_key}")

        # instantiate a symmetric enc scheme from this key
        serialized_key = self.helper.get_pairing_group().serialize(key)
        cipher = SymmetricCryptoAbstraction(hashlib.sha256(serialized_key).digest())
        sym_enc_file = cipher.encrypt(file)
        return {'abe_policy_enc_key': abe_policy_enc_key, 'sym_enc_file': sym_enc_file}

    def decrypt(self, user_keys, enc_file):
        abe_enc_session_key = enc_file['abe_policy_enc_key']
        key = self.helper.decrypt(user_keys, abe_enc_session_key)
        sym_enc_file = enc_file['sym_enc_file']
        serialized_key = self.helper.get_pairing_group().serialize(key)
        cipher = SymmetricCryptoAbstraction(hashlib.sha256(serialized_key).digest())
        return cipher.decrypt(sym_enc_file)

if __name__ == "__main__":

    ########## Example Usage ##########

    ma_abe_service = MAABEService()
    id_bob = "bob"
    usr_attrs_hospital = ['DOCTOR@HOSPITAL']
    usr_attrs_phr = ['PATIENT@PHR_1']
    user_keys_hospital = ma_abe_service.helper.gen_user_key('HOSPITAL', id_bob, usr_attrs_hospital)
    user_keys_phr = ma_abe_service.helper.gen_user_key('PHR', id_bob, usr_attrs_phr)

    user_keys_bob = {'GID': id_bob, 'keys': merge_dicts(user_keys_hospital, user_keys_phr)}

    id_alice = "alice"
    usr_attrs_employer = ['PATIENT@PHR_2']
    usr_attrs_insurance = ['INSURANCEREP@INSURANCE']
    user_keys_insurance = ma_abe_service.helper.gen_user_key('INSURANCE', id_alice, usr_attrs_insurance)
    user_keys_phr_2 = ma_abe_service.helper.gen_user_key('PHR', id_alice, usr_attrs_phr)

    user_keys_alice = {'GID': id_alice, 'keys': merge_dicts(user_keys_phr_2, user_keys_insurance)}

    # String message to encrypt
    message = "This is a secret message"

    policy = '((PATIENT@PHR_1 or DOCTOR@HOSPITAL))'

    enc_message = ma_abe_service.encrypt(message, policy)

    print(f"Encrypted file before serial/deserial: {enc_message}")

    abe_policy_enc_key = enc_message['abe_policy_enc_key']
    sym_enc_file = enc_message['sym_enc_file']

    # Serialize the encrypted AES key
    serial_abe_policy_enc_key = serialize_encrypted_aes_key(abe_policy_enc_key, ma_abe_service.group)
    # serialize encrypted file to JSON
    serial_enc_file = serialize_encrypted_data(sym_enc_file)

    # deserialize the encrypted AES key
    deserialized_abe_policy_enc_key = deserialize_encrypted_aes_key(serial_abe_policy_enc_key, ma_abe_service.group)
    # deserialize symmetrically encrypted file
    deserialized_enc_file = deserialize_encrypted_data(serial_enc_file)

    enc_message = {'abe_policy_enc_key': deserialized_abe_policy_enc_key, 'sym_enc_file': deserialized_enc_file}

    print(f"Encrypted file after serial/deserial: {enc_message}")


    decrypted_message = ma_abe_service.decrypt(user_keys_bob, enc_message)


    print(f"Decrypted file: {decrypted_message}")
