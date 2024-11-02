import requests
import json
import base64

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15

from services.constants import SERVER_URL, API_VERSION, PAIRING_GROUP
from services.database.database import db_save_public_parameters, db_initialize, db_get_user, \
    db_get_public_parameters, db_get_auth_pub_key, db_save_user, db_save_auth_pub_key
from services.ma_abe.ma_abe_service import MAABEService
from services.serialization.serial import deserialize_user_abe_keys, deserialize_ma_abe_public_parameters

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


def send_encrypted_message(user_uuid, abe_ciphertext_encoded, encrypted_message_encoded):
    """
    Send the encrypted AES key and encrypted message to the server.
    """
    url = f"{SERVER_URL}/user_message_aes_key/{user_uuid}"
    data = {
        'c_serial': abe_ciphertext_encoded,
        'aes_enc_message': encrypted_message_encoded,
        'message_type': 'text'  # Assuming 'text' is a valid message type
    }
    headers = {'Content-Type': 'application/json'}

    response = requests.post(url, data=json.dumps(data), headers=headers)

    if response.status_code == 201:
        print("Encrypted message sent successfully.")
    else:
        print(f"Error sending encrypted message: {response.text}")

def get_encrypted_messages(user_uuid):
    """
    Retrieve encrypted messages from the server.
    """
    url = f"{SERVER_URL}/get_user_message/{user_uuid}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        return data  # This should be a dictionary of message_id to encrypted data
    else:
        print(f"Error fetching messages: {response.text}")
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

# Example usage
if __name__ == "__main__":

    db_initialize()

    # User UUID
    user_uuid = '0'  # Replace with the actual UUID

    # Get public parameters from the server
    public_params = get_public_parameters()
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

    ma_abe_service = MAABEService()

    # Encrypt a message
    message = "This is a secret message."
    policy_str = 'PATIENT@PHR_0'
    print(f"Encrypting message under policy: {policy_str}")
    enc_message = ma_abe_service.encrypt(message, policy_str)

    # print the encrypted message
    print(f"Encrypted message: {enc_message}")
    # print the encrypted AES key
    print(f"Encrypted AES key: {enc_message['abe_policy_enc_key']}")

    # Send the encrypted message to the server
    # print("Sending encrypted message to the server...")
    # send_encrypted_message(user_uuid, abe_ciphertext_encoded, encrypted_message_encoded)
    #
    # # Retrieve encrypted messages from the server
    # print("Retrieving encrypted messages...")
    # messages = get_encrypted_messages(user_uuid)
    # if messages is None:
    #     exit()
    #

    print(user_keys)

    decrypted_message = ma_abe_service.decrypt(user_keys, enc_message)

    print(f"Decrypted message: {decrypted_message}")

