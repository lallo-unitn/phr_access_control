import hashlib

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

import controllers.constant as const
from charm.core.math.pairing import GT
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15, merge_dicts

# wanted to use abenc_maabe_yj14 since it supported key revocation but --> see https://github.com/JHUISI/charm/issues/287

# doc: https://jhuisi.github.io/charm/charm/schemes/abenc/abenc_maabe_rw15.html

class MaAbeInit:

    def __init__(self):
        # Initialize
        self.__key_pairs = {}
        self.__group = PairingGroup(const.PAIRING_GROUP)
        self.__ma_abe = MaabeRW15(self.__group)
        self.__public_parameters = self.__ma_abe.setup()
        self.__public_keys = {}

        # Dictionary to store auth names and corresponding attributes
        auth_attrs = {
            'PHR': ['PATIENT@PHR'],
            'HOSPITAL': ['DOCTOR@HOSPITAL'],
            'INSURANCE': ['INSURANCE_REP@INSURANCE'],
            'EMPLOYER': ['EMPLOYER_REP@EMPLOYER'],
            'HEALTH_CLUB': ['HEALTH_CLUB_TRAINER@HEALTH_CLUB']
        }

        # Loop through each auth and set up master secret keys and public keys
        for auth, attrs in auth_attrs.items():
            (public_key, secret_key) = self.__ma_abe.authsetup(self.__public_parameters, auth)
            print(f"Master Secret Key for {auth}: {secret_key}")
            self.__key_pairs[auth] = {
                'public_key': public_key,
                'secret_key': secret_key
            }
            self.__public_keys[auth] = public_key

    # Generate a key for a user
    def gen_user_key(self, auth, user_id, user_attrs):
        user_keys = self.__ma_abe.multiple_attributes_keygen(
            self.__public_parameters,
            self.__key_pairs[auth]['secret_key'],
            user_id,
            user_attrs
        )
        return user_keys

    # Merge keys
    def merge_keys(user_id, *user_keys):
        return {'user_id': user_id, 'keys': merge_dicts(*user_keys)}

    #encrypt the message
    def encrypt_msg(self, policy, msg):
        return self.__ma_abe.encrypt(self.__public_parameters, self.__public_keys, msg, policy)

    #decrypt the message
    def decrypt_msg(self, user_keys, cipher_text):
        return self.__ma_abe.decrypt(self.__public_parameters, user_keys, cipher_text)

    def get_pairing_group(self):
        return self.__group

if __name__ == "__main__":
    ma_abe_init = MaAbeInit()
    id_bob = "bob"
    usr_attrs_hospital = ['DOCTOR@HOSPITAL']
    usr_attrs_phr = ['PATIENT@PHR']
    user_keys_hospital = ma_abe_init.gen_user_key('HOSPITAL', id_bob, usr_attrs_hospital)
    user_keys_phr = ma_abe_init.gen_user_key('PHR', id_bob, usr_attrs_phr)
    print(f"User Keys for {id_bob}: {user_keys_hospital}")

    user_keys = {'GID': id_bob, 'keys': merge_dicts(user_keys_hospital, user_keys_phr)}

    # Your string message to encrypt
    message = "This is a secret message"

    # Generate a random session key (an element in GT)
    session_key = ma_abe_init.get_pairing_group().random(GT)

    # Derive a symmetric key from the session key
    session_key_bytes = ma_abe_init.get_pairing_group().serialize(session_key)
    sym_key = hashlib.sha256(session_key_bytes).digest()
    sym_crypto = SymmetricCryptoAbstraction(sym_key)

    # Encrypt the message using the symmetric key
    ciphertext = sym_crypto.encrypt(message)

    # Encrypt the session key using the ABE scheme
    policy = '((PATIENT@PHR and DOCTOR@HOSPITAL))'
    encrypted_session_key = ma_abe_init.encrypt_msg(policy, session_key)

    # Package the encrypted session key and ciphertext
    final_cipher = {
        'encrypted_session_key': encrypted_session_key,
        'ciphertext': ciphertext
    }

    print("Final Cipher: ", final_cipher)

    # Decryption process
    # Decrypt the session key using the ABE scheme
    decrypted_session_key = ma_abe_init.decrypt_msg(user_keys, final_cipher['encrypted_session_key'])

    # Derive the symmetric key from the decrypted session key
    decrypted_session_key_bytes = ma_abe_init.get_pairing_group().serialize(decrypted_session_key)
    sym_key = hashlib.sha256(decrypted_session_key_bytes).digest()
    sym_crypto = SymmetricCryptoAbstraction(sym_key)

    # Decrypt the message using the symmetric key
    decrypted_message = sym_crypto.decrypt(final_cipher['ciphertext']).decode('utf-8')

    print("Decrypted Message: ", decrypted_message)
    assert message == decrypted_message, "FAILED Decryption: message is incorrect"
    print("Successful Decryption!!!")
