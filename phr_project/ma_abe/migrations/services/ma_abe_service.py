import hashlib

from charm.core.math.pairing import GT
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.schemes.abenc.abenc_maabe_rw15 import merge_dicts
from ma_abe.migrations.utils.charm_helpers import CharmMAABEHelper

class MAABEService:
    def __init__(self):
        self.helper = CharmMAABEHelper()

    def encrypt(self, file, policy):
        key = self.helper.get_random_group_element()
        abe_policy_enc_key = self.helper.encrypt(key, policy)
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
    usr_attrs_phr = ['PATIENT@PHR']
    user_keys_hospital = ma_abe_service.helper.gen_user_key('HOSPITAL', id_bob, usr_attrs_hospital)
    user_keys_phr = ma_abe_service.helper.gen_user_key('PHR', id_bob, usr_attrs_phr)

    user_keys_bob = {'GID': id_bob, 'keys': merge_dicts(user_keys_hospital, user_keys_phr)}

    id_alice = "alice"
    usr_attrs_employer = ['EMPLOYERREP@EMPLOYER']
    usr_attrs_insurance = ['INSURANCEREP@INSURANCE']
    user_keys_employer = ma_abe_service.helper.gen_user_key('EMPLOYER', id_alice, usr_attrs_employer)
    user_keys_insurance = ma_abe_service.helper.gen_user_key('INSURANCE', id_alice, usr_attrs_insurance)

    user_keys_alice = {'GID': id_alice, 'keys': merge_dicts(user_keys_employer, user_keys_insurance)}

    # String message to encrypt
    message = "This is a secret message"
    message2 = "This is another a secret message"

    policy = '((PATIENT@PHR and DOCTOR@HOSPITAL))'
    policy2 = '((EMPLOYERREP@EMPLOYER and INSURANCEREP@INSURANCE))'

    enc_file = ma_abe_service.encrypt(message, policy)
    enc_file2 = ma_abe_service.encrypt(message2, policy2)

    print(f"Encrypted file: {enc_file}")
    print(f"Encrypted file2: {enc_file2}")

    decrypted_file = ma_abe_service.decrypt(user_keys_bob, enc_file)
    decrypted_file2 = ma_abe_service.decrypt(user_keys_alice, enc_file2)

    print(f"Decrypted file: {decrypted_file}")
    print(f"Decrypted file2: {decrypted_file2}")


    # # Generate a random session key (an element in GT)
    # session_key = ma_abe_service.helper.generate_session_key()
    #
    # #print session key
    # print(f"Session key: {session_key}")
    #
    # policy = '((PATIENT@PHR and DOCTOR@HOSPITAL))'
    #
    # # Encrypt the session key using the ABE scheme and store it in the enc_session_keys dictionary
    # ma_abe_service.set_abe_encrypted_session_key(policy, session_key)
    #
    # # print the encrypted session key
    # print(f"Encrypted session key: {ma_abe_service.get_abe_encrypted_session_key(policy)}")
    #
    # # Encrypt the file using the symmetric key and return the encrypted file and the ABE encrypted session key
    # enc_file = ma_abe_service.encrypt_file(message, policy, session_key)
    #
    # policy2 = '((EMPLOYERREP@EMPLOYER and INSURANCEREP@INSURANCE))'
    #
    # enc_file2 = ma_abe_service.encrypt_file(message2, policy2, session_key)
    #
    # print(f"Encrypted session key: {ma_abe_service.get_abe_encrypted_session_key(policy2)}")
    #
    # # print the encrypted file
    # print(f"Encrypted file: {enc_file}")
    #
    # decrypted_session_key = ma_abe_service.decrypt_session_key(user_keys_bob, enc_file['abe_enc_session_key'])
    #
    # #print the decrypted session key
    # print(f"Decrypted session key: {decrypted_session_key}")
    #
    # decrypted_session_key2 = ma_abe_service.decrypt_session_key(user_keys_alice, enc_file2['abe_enc_session_key'])
    #
    # print(f"Decrypted session key2: {decrypted_session_key2}")
    #
    # # Decrypt the file using the symmetric key
    # decrypted_file = ma_abe_service.decrypt_file(user_keys_bob, enc_file)
    #
    # decrypted_file2 = ma_abe_service.decrypt_file(user_keys_alice, enc_file2)
    #
    # print(f"Decrypted file: {decrypted_file2}")
    #
    # #print the decrypted file
    # print(f"Decrypted file: {decrypted_file}")
