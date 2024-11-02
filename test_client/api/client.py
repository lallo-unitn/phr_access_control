import requests
import json
import base64

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15

from services.constants import SERVER_URL, API_VERSION, PAIRING_GROUP, TEST_AUTH_ATTRS
from services.database.database import db_save_public_parameters, db_initialize, db_get_user, \
    db_get_public_parameters, db_get_auth_pub_key, db_save_user, db_save_auth_pub_key
from services.ma_abe.ma_abe_service import MAABEService
from services.serialization.serial import deserialize_user_abe_keys, deserialize_ma_abe_public_parameters, \
    deserialize_auth_public_key, serialize_encrypted_aes_key, serialize_encrypted_data, deserialize_encrypted_aes_key, \
    deserialize_encrypted_data

# Initialize the pairing group and MAABE scheme
group = PairingGroup(PAIRING_GROUP)
ma_abe = MaabeRW15(group)

def get_public_parameters():
    """
    Obtain the public parameters from the server.
    """
    url = f"{SERVER_URL}/{API_VERSION}/public_parameters"

    serial_public_parameters = db_get_public_parameters()
    if serial_public_parameters is not None:
        public_parameters = deserialize_ma_abe_public_parameters(group, serial_public_parameters)
        return public_parameters

    response = requests.get(url)

    if response.status_code == 200:
        # b64_serial_public_parameters is in form of
        # {
            # 'serial_g1': b64.b64encode(public_parameters.g1_serial).decode('utf-8'),
            # 'serial_g2': b64.b64encode(public_parameters.g2_serial).decode('utf-8'),
            # 'serial_egg': b64.b64encode(public_parameters.egg_serial).decode('utf-8')
        # }
        b64_serial_public_parameters = response.json()
        serial_public_parameters = {k: base64.b64decode(v) for k, v in b64_serial_public_parameters.items()}
        db_save_public_parameters(serial_public_parameters)
        public_parameters = deserialize_ma_abe_public_parameters(group, serial_public_parameters)
        return public_parameters
    else:
        print(f"Error fetching public parameters: {response.text}")
        return None, None

def get_serialized_user_secret_key(user_uuid):
    """
    Obtain the user's secret key from the server.
    """
    url = f"{SERVER_URL}/{API_VERSION}/user_setup/{user_uuid}"
    # search for user in the database
    user = db_get_user(user_uuid)
    # if user is not in the database, fetch from the server new keys and save them
    if user is None:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            db_save_user(user_uuid, data)
            return data
        else:
            print(f"Error fetching user secret key: {response.text}")
            return None
    else:
        return user['keys']


def send_encrypted_message(user_uuid, enc_message, type):
    """
    Send the encrypted AES key and encrypted message to the server.
    """
    url = f"{SERVER_URL}/{API_VERSION}/user/{user_uuid}/message/0"

    serial_abe_policy_enc_key = serialize_encrypted_aes_key(enc_message['abe_policy_enc_key'], group)
    serial_enc_message = serialize_encrypted_data(enc_message['sym_enc_file'])

    b64_serial_abe_policy_enc_key = base64.b64encode(serial_abe_policy_enc_key).decode('utf-8')
    b64_serial_enc_message = base64.b64encode(serial_enc_message).decode('utf-8')

    data = {
        'b64_serial_abe_policy_enc_key': b64_serial_abe_policy_enc_key,
        'b64_serial_enc_message': b64_serial_enc_message,
        'message_type': type
    }

    headers = {'Content-Type': 'application/json'}

    response = requests.post(url, data=json.dumps(data), headers=headers)

    if response.status_code == 201:
        print("Encrypted message sent successfully.")
    else:
        print(f"Error sending encrypted message: {response.text}")

def get_encrypted_message(user_uuid, message_id):
    """
    Obtain the encrypted messages from the server.
    """

    # message_data = {
    #             'b64_serial_aes_key': b64_serial_aes_key,
    #             'b64_serial_enc_message': b64_serial_enc_message,
    #             'message_type': message.message_type
    #         }

    url = f"{SERVER_URL}/{API_VERSION}/user/{user_uuid}/message/{message_id}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        serial_abe_policy_enc_key = base64.b64decode(data['b64_serial_aes_key'])
        serial_enc_message = base64.b64decode(data['b64_serial_enc_message'])
        enc_message = {
            'abe_policy_enc_key': deserialize_encrypted_aes_key(serial_abe_policy_enc_key, group),
            'sym_enc_file': deserialize_encrypted_data(serial_enc_message)
        }
        type = data['message_type']
        return enc_message, type
    else:
        print(f"Error fetching encrypted messages: {response.text}")
        return None

def get_auth_pub_key(auth_id):
    """
    Obtain the public key of the authority from the server.
    """
    url = f"{SERVER_URL}/{API_VERSION}/auth_public_key/{auth_id}"

    if db_get_auth_pub_key(auth_id) is not None:
        return db_get_auth_pub_key(auth_id)

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        db_save_auth_pub_key(auth_id, data)
        return data
    else:
        print(f"Error fetching authority public key: {response.text}")
        return None

def init():
    db_initialize()
    ma_abe_service = MAABEService()

    # Get public parameters from the server
    public_params = get_public_parameters()
    auth_pub_key = {}
    for auth_id in TEST_AUTH_ATTRS.keys():
        auth_pub_key[auth_id] = get_auth_pub_key(auth_id)
        # print(auth_pub_key[auth_id])
        auth_pub_key[auth_id] = deserialize_auth_public_key(group, auth_pub_key[auth_id])

    ma_abe_service.helper.set_auth_public_keys(auth_pub_key)

    return public_params, ma_abe_service

# Example usage
if __name__ == "__main__":

    public_params,ma_abe_service = init()

    user_uuid = '0'

    # print public parameters
    print(f"Public parameters: {public_params}")
    # Obtain user's secret keys
    print("Fetching user's secret keys...")
    # first check if user's secret keys are in the database
    # if not, fetch from the server and save in the database
    serial_user_keys = get_serialized_user_secret_key(user_uuid)
    if serial_user_keys is None:
        exit()

    user_keys = deserialize_user_abe_keys(group, serial_user_keys)

    # Encrypt a message
    message = "This is a secret message."
    policy_str = 'PATIENT@PHR_0 or DOCTOR@HOSPITAL1'
    print(f"Encrypting message under policy: {policy_str}")
    enc_message = ma_abe_service.encrypt(message, policy_str)

    # print the encrypted message
    print(f"Encrypted message: {enc_message}")
    # print the encrypted AES key
    print(f"Encrypted AES key: {enc_message['abe_policy_enc_key']}")

    # Send the encrypted message to the server
    print("Sending encrypted message to the server...")
    # send_encrypted_message(user_uuid, enc_message, "HEALTH")
    #
    # # Retrieve encrypted messages from the server
    # print("Retrieving encrypted messages...")
    enc_message_srv, type = get_encrypted_message(user_uuid, 2)
    if enc_message_srv is None:
         exit()
    #

    # print(user_keys)

    print(f"Encrypted message: {enc_message}")
    print(f"Encrypted message: {enc_message_srv}")

    decrypted_message = ma_abe_service.decrypt(user_keys, enc_message)
    decrypted_message_srv = ma_abe_service.decrypt(user_keys, enc_message_srv)

    print(f"Decrypted message: {decrypted_message}")
    print(f"Decrypted message: {decrypted_message_srv}")
