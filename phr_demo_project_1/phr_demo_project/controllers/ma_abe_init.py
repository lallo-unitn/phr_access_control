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

    msg = ma_abe_init.get_pairing_group().random(GT)
    print("Message: ", msg)

    policy = '((PATIENT@PHR and DOCTOR@HOSPITAL))'

    cipher_text = ma_abe_init.encrypt_msg(policy, msg)
    print("Cipher Text: ", cipher_text)

    rec_msg_1 = ma_abe_init.decrypt_msg(user_keys, cipher_text)
    assert msg == rec_msg_1, "FAILED Decryption: message is incorrect"
    print("Successful Decryption!!!")
