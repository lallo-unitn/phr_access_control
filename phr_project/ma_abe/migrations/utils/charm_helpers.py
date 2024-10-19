from attr.validators import instance_of
from charm.core.math.pairing import GT
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup
import ma_abe.migrations.utils.constants as const

class CharmMAABEHelper:
    def __init__(self):
        self.__public_keys = None
        self.__public_parameters = None
        self.__key_pairs = {}
        self.__group = PairingGroup(const.PAIRING_GROUP)
        self.__ma_abe = MaabeRW15(self.__group)
        self.__public_keys = {}

        # Dictionary to store auth names and corresponding attributes
        self.auth_attrs = {
            'PHR': ['PATIENT@PHR'],
            'HOSPITAL': ['DOCTOR@HOSPITAL'],
            'INSURANCE': ['INSURANCEREP@INSURANCE'],
            'EMPLOYER': ['EMPLOYER_REP@EMPLOYER'],
            'HEALTH_CLUB': ['HEALTHCLUBTRAINER@HEALTHCLUB']
        }

        self.setup()

        for auth, attrs in self.auth_attrs.items():
            (public_key, secret_key) = self.__ma_abe.authsetup(self.__public_parameters, auth)
            # print(f"Public Key for {auth}: {self.__group.serialize(public_key['egga'])}")
            # print(f"Public Key for {auth}: {self.__group.serialize(public_key['gy'])}")
            # print(f"Public Key for {auth}: {self.__group.serialize(secret_key['alpha'])}")
            # print(f"Public Key for {auth}: {self.__group.serialize(secret_key['y'])}")
            # print(f"Master Secret Key for {auth}: {secret_key}")
            self.__key_pairs[auth] = {
                'public_key': public_key,
                'secret_key': secret_key
            }
            self.__public_keys[auth] = public_key

    # returns
    # gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F}
    def setup(self):
        self.__public_parameters = self.__ma_abe.setup()
        # g1_str = self.__group.serialize(self.__public_parameters['g1'])
        # print(type(g1_str))
        # print(f"Public Parameters: {g1_str}")
        # g1 = self.__group.deserialize(g1_str)
        # print(f"Public Parameters: {g1}")
        print(f"Public Parameters: {self.__public_parameters}")

    def get_random_group_element(self):
        return self.__group.random(GT)

    def get_pairing_group(self):
        return self.__group

    # returns
    # pk = {'name': name, 'egga': egga, 'gy': gy} and
    # sk = {'name': name, 'alpha': alpha, 'y': y}
    def __auth_setup(self, auth_name):
        (public_key, secret_key) = (
            self.__ma_abe.authsetup(
                self.__public_parameters,
                auth_name
            )
        )
        return public_key, secret_key


    def set_auth_key_pairs(self, auth_name):
        (public_key, secret_key) = (
            self.__auth_setup(auth_name)
        )
        self.__key_pairs[auth_name] = {
            'public_key': public_key,
            'secret_key': secret_key
        }
        self.__public_keys[auth_name] = public_key

    # returns a dictionary with attribute names as keys,
    # and secret keys for the attributes as values.
    # for every attribute, put in dictionary {'K': K, 'KP': KP}
    # that is the secret key for the attribute for the user with identifier gid.
    def gen_user_key(self, auth, user_id, user_attrs):
        user_keys = self.__ma_abe.multiple_attributes_keygen(
            self.__public_parameters,
            self.__key_pairs[auth]['secret_key'],
            user_id,
            user_attrs
        )
        return user_keys

    # encrypt the message and return in the form
    # {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}
    # NOTE THAT every attribute must be in the form of
    # attr = "%s@%s" % (attribute_name, auth_name)
    def encrypt(self, msg, policy):
        return self.__ma_abe.encrypt(self.__public_parameters, self.__public_keys, msg, policy)

    # raises exception when the access policy can not be
    # satisfied with the user's attributes.
    def decrypt(self, user_keys, cipher_text):
        return self.__ma_abe.decrypt(self.__public_parameters, user_keys, cipher_text)
