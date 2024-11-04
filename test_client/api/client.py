import base64
import json

import requests
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup

from services.constants import API_VERSION, PAIRING_GROUP, SERVER_URL, TEST_AUTH_ATTRS
from services.database.database import (
    db_get_auth_pub_key,
    db_get_public_parameters,
    db_get_user,
    db_initialize,
    db_save_auth_pub_key,
    db_save_public_parameters,
    db_save_user,
)
from services.ma_abe.ma_abe_service import MAABEService
from services.serialization.serial import (
    deserialize_auth_public_key,
    deserialize_encrypted_abe_ciphertext,
    deserialize_encrypted_data,
    deserialize_ma_abe_public_parameters,
    deserialize_user_abe_keys,
    serialize_encrypted_abe_ciphertext,
    serialize_encrypted_data,
)

# Initialize the pairing group and MAABE scheme
group = PairingGroup(PAIRING_GROUP)
ma_abe = MaabeRW15(group)


def prepare_message(enc_message, message_type):
    """
    Prepare the encrypted message data to be sent to the server.

    Args:
        enc_message (dict): Encrypted message containing 'abe_policy_enc_key' and 'sym_enc_file'.
        message_type (str): Type of the message.

    Returns:
        dict: Data dictionary containing base64 encoded serialized encrypted components.
    """
    serial_abe_policy_enc_key = serialize_encrypted_abe_ciphertext(
        enc_message['abe_policy_enc_key'], group
    )
    serial_enc_message = serialize_encrypted_data(enc_message['sym_enc_file'])

    b64_serial_abe_policy_enc_key = base64.b64encode(serial_abe_policy_enc_key).decode('utf-8')
    b64_serial_enc_message = base64.b64encode(serial_enc_message).decode('utf-8')

    data = {
        'b64_serial_abe_policy_enc_key': b64_serial_abe_policy_enc_key,
        'b64_serial_enc_message': b64_serial_enc_message,
        'message_type': message_type,
    }

    return data


def get_public_parameters():
    """
    Obtain the public parameters from the server or from the local database.

    Returns:
        dict: Deserialized public parameters.
    """
    url = f"{SERVER_URL}/{API_VERSION}/public_parameters"

    # Try to get public parameters from the local database
    serial_public_parameters = db_get_public_parameters()
    if serial_public_parameters is not None:
        public_parameters = deserialize_ma_abe_public_parameters(group, serial_public_parameters)
        return public_parameters

    # Fetch public parameters from the server
    response = requests.get(url)
    if response.status_code == 200:
        b64_serial_public_parameters = response.json()
        # Decode base64 serialized public parameters
        serial_public_parameters = {
            k: base64.b64decode(v) for k, v in b64_serial_public_parameters.items()
        }
        # Save to local database
        db_save_public_parameters(serial_public_parameters)
        public_parameters = deserialize_ma_abe_public_parameters(group, serial_public_parameters)
        return public_parameters
    else:
        print(f"Error fetching public parameters: {response.text}")
        return None


def get_serialized_user_secret_key(user_uuid):
    """
    Obtain the user's secret key from the server or from the local database.

    Args:
        user_uuid (str): User's UUID.

    Returns:
        dict: Serialized user's secret keys.
    """
    url = f"{SERVER_URL}/{API_VERSION}/user_setup/{user_uuid}"

    # Try to get user keys from the local database
    user = db_get_user(user_uuid)
    if user is not None:
        return user['keys']

    # Fetch user secret keys from the server
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Save to local database
        db_save_user(user_uuid, data)
        return data
    else:
        print(f"Error fetching user secret key: {response.text}")
        return None


def send_encrypted_message(user_uuid, enc_message, message_type):
    """
    Send the encrypted AES key and encrypted message to the server.

    Args:
        user_uuid (str): User's UUID.
        enc_message (dict): Encrypted message components.
        message_type (str): Type of the message.

    Returns:
        None
    """
    url = f"{SERVER_URL}/{API_VERSION}/user/{user_uuid}/message/0"
    data = prepare_message(enc_message, message_type)
    headers = {'Content-Type': 'application/json'}

    response = requests.post(url, data=json.dumps(data), headers=headers)
    if response.status_code == 201:
        print("Encrypted message sent successfully.")
    else:
        print(f"Error sending encrypted message: {response.text}")


def get_encrypted_message(user_uuid, message_id):
    """
    Obtain the encrypted message from the server.

    Args:
        user_uuid (str): User's UUID.
        message_id (int): Message ID.

    Returns:
        tuple: (enc_message (dict), message_type (str))
    """
    url = f"{SERVER_URL}/{API_VERSION}/user/{user_uuid}/message/{message_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        serial_abe_policy_enc_key = base64.b64decode(data['b64_serial_abe_policy_enc_key'])
        serial_enc_message = base64.b64decode(data['b64_serial_enc_message'])
        enc_message = {
            'abe_policy_enc_key': deserialize_encrypted_abe_ciphertext(
                serial_abe_policy_enc_key, group
            ),
            'sym_enc_file': deserialize_encrypted_data(serial_enc_message),
        }
        message_type = data['message_type']
        return enc_message, message_type
    else:
        print(f"Error fetching encrypted message: {response.text}")
        return None, None


def get_auth_pub_key(auth_id):
    """
    Obtain the public key of the authority from the server or from the local database.

    Args:
        auth_id (str): Authority ID.

    Returns:
        dict: Authority's public key.
    """
    url = f"{SERVER_URL}/{API_VERSION}/auth_public_key/{auth_id}"

    # Try to get authority public key from the local database
    auth_pub_key = db_get_auth_pub_key(auth_id)
    if auth_pub_key is not None:
        return auth_pub_key

    # Fetch authority public key from the server
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Save to local database
        db_save_auth_pub_key(auth_id, data)
        return data
    else:
        print(f"Error fetching authority public key: {response.text}")
        return None


def get_policy_doc_ins_emp(user_uuid):
    """
    Obtain the policy from the server.

    Args:
        user_uuid (str): User's UUID.

    Returns:
        str: Policy string.
    """
    url = f"{SERVER_URL}/{API_VERSION}/policy_doc_ins_emp/{user_uuid}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['policy']
    else:
        print(f"Error fetching policy: {response.text}")
        return None


def get_challenge_hospital_patient(rep_id, patient_id, auth:str):
    """
    Get the challenge from the server for a given doctor and patient.

    Args:
        doctor_id (str): Doctor's ID.
        patient_id (str): Patient's ID.

    Returns:
        dict: Challenge data from the server.
    """
    if "HOSPITAL" in auth:
        challenge_url = f"{SERVER_URL}/{API_VERSION}/hospital/{rep_id}/patient/{patient_id}/message"
    elif "HEALTHCLUB" in auth:
        challenge_url = f"{SERVER_URL}/{API_VERSION}/healthclub/{rep_id}/patient/{patient_id}/message"
    else:
        print("Invalid authority.")
        return

    response = requests.get(challenge_url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching challenge: {response.text}")
        return None


def post_message_auth_patient(
    rep_id, patient_id, decrypted_challenge, rep_message, policy, auth, ma_abe_service
):
    """
    Post a message from the authority to the patient.

    Args:
        rep_id (str): Representative ID.
        patient_id (str): Patient ID.
        decrypted_challenge (str): Decrypted challenge string.
        rep_message (str): Representative message to send.
        policy (str): Policy string for encryption.
        auth (str): Authority string.
        ma_abe_service (MAABEService): Instance of MAABEService.

    Returns:
        None
    """
    if "HOSPITAL" in auth:
        message_type = "HEALTH"
        challenge_url = f"{SERVER_URL}/{API_VERSION}/hospital/{rep_id}/patient/{patient_id}/message"
    elif "HEALTHCLUB" in auth:
        message_type = "TRAINING"
        challenge_url = f"{SERVER_URL}/{API_VERSION}/healthclub/{rep_id}/patient/{patient_id}/message"
    else:
        print("Invalid authority.")
        return

    b64_serial_challenge = base64.b64encode(group.serialize(decrypted_challenge)).decode('utf-8')

    print(f"Representative message: {rep_message}")

    enc_rep_message = ma_abe_service.encrypt(rep_message, policy)

    b64_serial_rep_message = prepare_message(enc_rep_message, message_type)

    data = {
        'b64_serial_challenge': b64_serial_challenge,
        'b64_serial_rep_message': b64_serial_rep_message,
    }

    headers = {'Content-Type': 'application/json'}
    response = requests.post(challenge_url, data=json.dumps(data), headers=headers)

    if response.status_code == 201:
        print("Message sent successfully.")
    else:
        print(f"Error sending message: {response.text}")


def post_rep_message(hospital_message, doctor_id, patient_id, policy, auth, ma_abe_service):
    """
    Post a representative message to the server after decrypting the challenge.

    Args:
        hospital_message (str): The message to be sent.
        doctor_id (str): Doctor's ID.
        patient_id (str): Patient's ID.
        policy (str): Policy string for encryption.
        auth (str): Authority string.
        ma_abe_service (MAABEService): Instance of MAABEService.

    Returns:
        None
    """

    if "HOSPITAL" not in auth and "HEALTHCLUB" not in auth:
        print("Invalid authority.")
        return

    # Get challenge
    challenge_data = get_challenge_hospital_patient(doctor_id, patient_id, auth)
    if not challenge_data:
        return

    b64_serial_challenge = challenge_data['b64_serial_challenge']
    serial_challenge = base64.b64decode(b64_serial_challenge)
    challenge = deserialize_encrypted_abe_ciphertext(serial_challenge, group)

    serial_doctor_keys = get_serialized_user_secret_key(doctor_id)
    doctor_keys = deserialize_user_abe_keys(group, serial_doctor_keys)

    decrypted_challenge = ma_abe_service.helper.decrypt(
        user_keys=doctor_keys,
        cipher_text=challenge,
    )

    post_message_auth_patient(
        doctor_id,
        patient_id,
        decrypted_challenge,
        hospital_message,
        policy,
        auth,
        ma_abe_service,
    )


def init():
    """
    Initialize the database, MAABE service, and set authority public keys.

    Returns:
        tuple: (public_parameters, ma_abe_service)
    """
    db_initialize()
    ma_abe_service = MAABEService()

    # Get public parameters from the server
    public_parameters = get_public_parameters()

    # Fetch and set authority public keys
    auth_pub_keys = {}
    for auth_id in TEST_AUTH_ATTRS.keys():
        auth_pub_key_data = get_auth_pub_key(auth_id)
        if auth_pub_key_data is not None:
            auth_pub_keys[auth_id] = deserialize_auth_public_key(group, auth_pub_key_data)

    ma_abe_service.helper.set_auth_public_keys(auth_pub_keys)

    return public_parameters, ma_abe_service


# Example usage
if __name__ == "__main__":
    public_params, ma_abe_service = init()
    user_uuid = '0'

    # Print public parameters
    print(f"Public parameters: {public_params}")

    # Obtain user's secret keys
    print("Fetching user's secret keys...")
    serial_user_keys = get_serialized_user_secret_key(user_uuid)
    if serial_user_keys is None:
        exit("User's secret keys could not be obtained.")

    user_keys = deserialize_user_abe_keys(group, serial_user_keys)

    # Encrypt a message
    message = "This is a secret message."
    policy_str = get_policy_doc_ins_emp(user_uuid)
    print(f"Encrypting message under policy: {policy_str}")
    enc_message = ma_abe_service.encrypt(message, policy_str)
    #
    # # Print the encrypted AES key
    print(f"Encrypted AES key: {enc_message['abe_policy_enc_key']}")
    #
    # # Send the encrypted message to the server
    print("Sending encrypted message to the server...")
    send_encrypted_message(user_uuid, enc_message, "HEALTH")
    #
    # # Retrieve encrypted messages from the server
    print("Retrieving encrypted messages...")
    enc_message_srv, message_type = get_encrypted_message(user_uuid, 11)
    if enc_message_srv is None:
        exit("No encrypted messages retrieved from the server.")
    #
    # Decrypt the message
    decrypted_message = ma_abe_service.decrypt(user_keys, enc_message_srv)
    print(f"Decrypted message: {decrypted_message}")

    # Post representative message
    rep_id = '11'
    patient_id = '4'
    policy = '(DOCTOR@HOSPITAL1)'
    auth = 'HEALTHCLUB1'

    post_rep_message(message, rep_id, patient_id, policy, auth, ma_abe_service)
