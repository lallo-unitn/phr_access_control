from charm.core.math.pairing import GT
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup
import accounts.utils.constants as const
from accounts.models import MAABEPublicParams, Authority, add_public_params, add_authority
from accounts.utils.serial import serialize_ma_abe_public_parameters, deserialize_ma_abe_public_parameters, \
    serialize_auth_key_pair, deserialize_auth_key_pair


class CharmMAABEHelper:
    def __init__(self):
        self.__public_keys = None
        self.__public_parameters = None
        self.__key_pairs = {}
        self.__group = PairingGroup(const.PAIRING_GROUP)
        self.__ma_abe = MaabeRW15(self.__group)
        self.__public_keys = {}
        self.__is_setup = False

        self.__setup()
        self.__authorities_setup(const.TEST_AUTH_ATTRS)

    def __setup(self):
        if self.__public_params_is_setup():
            # load parameters
            self.__public_parameters = self.__load_public_parameters()
            self.__is_setup = True
        else:
            # compute params
            self.__public_parameters = self.__ma_abe.setup()
            # save params
            self.__save_public_parameters(self.__public_parameters)
            self.__is_setup = True
        # print(f"Public Parameters: {self.__public_parameters}")

    def __authorities_setup(self, auth_attrs):
        for auth, attrs in auth_attrs.items():
            if self.__authorities_keys_is_setup(auth):
                public_key, secret_key = self.__load_authority_keys(auth)
            else:
                (public_key, secret_key) = self.__ma_abe.authsetup(
                    self.__public_parameters,
                    auth
                )
                self.__save_authority_keys(
                    auth=auth,
                    public_key=public_key,
                    secret_key=secret_key
                )

            self.__key_pairs[auth]: dict= {
                'public_key': public_key,
                'secret_key': secret_key
            }
            self.__public_keys[auth] = public_key
        print(f"Public Keys: {self.__public_keys}")

    def get_random_group_element(self):
        return self.__group.random(GT)

    def get_pairing_group(self):
        return self.__group

    # returns a dictionary with attribute names as keys,
    # and secret keys for the attributes as values.
    # for every attribute, put in dictionary {'K': K, 'KP': KP}
    # that is the secret key for the attribute for the user with identifier gid.
    def gen_user_key(self, auth, user_id, user_attrs):
        print("Generating user key")
        print(self.__key_pairs[auth])

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

    def unpack_attribute(self, user_attr):
        return self.__ma_abe.unpack_attribute(user_attr)

    def merge_dicts(self, dict1, dict2):
        return {**dict1, **dict2}

    def __public_params_is_setup(self):
        return MAABEPublicParams.objects.exists()

    def __save_public_parameters(self, __public_parameters):
        serial_params_dict: dict = serialize_ma_abe_public_parameters(
            group=self.__group,
            public_parameters=self.__ma_abe.setup()
        )

        add_public_params(
            g1_serial=serial_params_dict['serial_g1'],
            g2_serial=serial_params_dict['serial_g2'],
            egg_serial=serial_params_dict['serial_egg']
        )

    def __load_public_parameters(self):
        try:
            public_param = MAABEPublicParams.objects.get(
                id=const.DEFAULT_ABE_PUBLIC_PARAMS_INDEX
            )

            print(f"ID: {public_param.id}")
            print(f"g1_serial: {public_param.g1_serial}")
            print(f"g2_serial: {public_param.g2_serial}")
            print(f"egg_serial: {public_param.egg_serial}")

            # load dict
            public_params = {
                'serial_g1': public_param.g1_serial,
                'serial_g2': public_param.g2_serial,
                'serial_egg': public_param.egg_serial
            }

            deserial_public_params = deserialize_ma_abe_public_parameters(
                group=self.__group,
                serial_params=public_params
            )

            return deserial_public_params
        except MAABEPublicParams.DoesNotExist:
            print("Public parameter with the given ID does not exist.")

    def __authorities_keys_is_setup(self, auth_name):
        try:
            # Get the Authority with the given name
            authority = Authority.objects.get(name=auth_name)

            # Check if sec_key and pub_key have values
            if authority.sec_key and authority.pub_key:
                return True
            else:
                return False

        except Authority.DoesNotExist:
            # Authority with the given name does not exist
            return False

    def __load_authority_keys(self, auth_name):
        try:
            # Get the Authority object with the given name
            authority = Authority.objects.get(
                name=auth_name
            )

            # Retrieve the sec_key and pub_key from the Authority object
            serial_sec_key = authority.sec_key
            serial_pub_key = authority.pub_key

            deserial_key_pair = deserialize_auth_key_pair(
                group=self.__group,
                serial_key_pair={
                    'auth_name': auth_name,
                    'serial_public_key_egga': serial_pub_key.egga_serial,
                    'serial_public_key_gy': serial_pub_key.gy_serial,
                    'serial_secret_key_alpha': serial_sec_key.alpha_serial,
                    'serial_secret_key_y': serial_sec_key.y_serial
                }
            )

            # Check if the keys exist and return them
            if deserial_key_pair['public_key'] and deserial_key_pair['secret_key']:
                return deserial_key_pair['public_key'], deserial_key_pair['secret_key']
            else:
                return None, None

        except Authority.DoesNotExist:
            # Authority with the given name does not exist
            return None, None

    def __save_authority_keys(self, auth, public_key, secret_key):

        serial_keys: dict = serialize_auth_key_pair(
            group=self.__group,
            auth_name=auth,
            public_key=public_key,
            secret_key=secret_key
        )

        add_authority(auth_id=auth, serial_keys=serial_keys)
