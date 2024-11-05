import base64
import json

import requests
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup

from services.constants import API_VERSION, PAIRING_GROUP, SERVER_URL
from services.database.database import (
    db_get_auth_pub_key,
    db_get_public_parameters,
    db_save_auth_pub_key,
    db_save_public_parameters, db_get_rep, db_get_patient, db_save_patient, db_save_rep
)
from services.ma_abe.ma_abe_service import MAABEService
from services.serialization.serial import (
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

def get_serialized_patient_secret_key(user_uuid):
    """
    Obtain the patient's secret key from the server or from the local database.

    Args:
        user_uuid (str): User's UUID.

    Returns:
        dict: Serialized user's secret keys.
    """

    url = f"{SERVER_URL}/{API_VERSION}/patient/{user_uuid}/keys"
    user = db_get_patient(user_uuid)

    if user is not None:
        return user['keys']

    # Fetch user secret keys from the server
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Save to local database
        db_save_patient(user_uuid, data)
        return data
    else:
        print(f"Error fetching user secret key: {response.text}")
        return None


def get_serialized_rep_secret_key(user_uuid):
    """
    Obtain the representative's secret key from the server or from the local database.

    Args:
        user_uuid (str): User's UUID.

    Returns:
        dict: Serialized user's secret keys.
    """

    url = f"{SERVER_URL}/{API_VERSION}/rep/{user_uuid}/keys"
    user = db_get_rep(user_uuid)

    if user is not None:
        return user['keys']

    # Fetch user secret keys from the server
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Save to local database
        db_save_rep(user_uuid, data)
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
        auth: authority
        rep_id (str): Representative's ID.
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

    if response.status_code == 201 or response.status_code == 200:
        print("Message sent successfully.")
    else:
        print(f"Error sending message: {response.text}")


def post_rep_message(rep_message, doctor_id, patient_id, policy, auth, ma_abe_service):
    """
    Post a representative message to the server after decrypting the challenge.

    Args:
        rep_message (str): The message to be sent.
        doctor_id (str): Doctor's ID.
        patient_id (str): Patient's ID.
        policy (str): Policy string for encryption.
        auth (str): Authority string.
        ma_abe_service (MAABEService): Instance of MAABEService.

    Returns:
        None
    """

    if "HOSPITAL" not in auth and "HEALTHCLUB" not in auth:
        print("The authority must be either HOSPITAL or HEALTHCLUB.")

    # Get challenge
    challenge_data = get_challenge_hospital_patient(doctor_id, patient_id, auth)
    if not challenge_data:
        return

    b64_serial_challenge = challenge_data['b64_serial_challenge']
    serial_challenge = base64.b64decode(b64_serial_challenge)
    challenge = deserialize_encrypted_abe_ciphertext(serial_challenge, group)

    serial_rep_keys = get_serialized_rep_secret_key(doctor_id)
    doctor_keys = deserialize_user_abe_keys(group, serial_rep_keys)

    decrypted_challenge = ma_abe_service.helper.decrypt(
        user_keys=doctor_keys,
        cipher_text=challenge,
    )

    try:
        post_message_auth_patient(
            doctor_id,
            patient_id,
            decrypted_challenge,
            rep_message,
            policy,
            auth,
            ma_abe_service,
        )
        return True

    except Exception as e:
        print(f"Error posting message: {e}")
        return False

def get_patients_list():
    """
    Get the list of patients from the server.

    Returns:
        list: List of patients.
    """
    url = f"{SERVER_URL}/{API_VERSION}/patients"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching patients: {response.text}")
        return None

def get_representatives_list():
    """
    Get the list of representatives from the server.

    Returns:
        list: List of representatives.
    """
    url = f"{SERVER_URL}/{API_VERSION}/representatives"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching representatives: {response.text}")
        return None
