from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup

from api.api import get_public_parameters, get_auth_pub_key, get_policy_doc_ins_emp, \
    send_message, get_encrypted_message, post_rep_message, get_patients_list, get_representatives_list, \
    get_serialized_patient_secret_key, get_serialized_rep_secret_key
from services.constants import TEST_AUTH_ATTRS, PAIRING_GROUP
from services.database.database import (
    db_initialize, db_get_rep,
)
from services.ma_abe.ma_abe_service import MAABEService
from services.serialization.serial import (
    deserialize_auth_public_key,
    deserialize_user_abe_keys,
)

# Initialize the pairing group and MAABE scheme
group = PairingGroup(PAIRING_GROUP)
ma_abe = MaabeRW15(group)

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
def test():
    public_params, ma_abe_service = init()
    user_uuid_writer = '0'
    user_uuid_reader = '1'

    # Print public parameters
    print(f"Public parameters: {public_params}")

    # Obtain user's secret keys
    print("Fetching user's secret keys...")
    serial_user_keys_writer = get_serialized_patient_secret_key(user_uuid_writer)
    serial_user_keys_reader = get_serialized_patient_secret_key(user_uuid_reader)
    if user_uuid_writer is None:
        exit("User's secret keys could not be obtained.")

    user_keys_writer = deserialize_user_abe_keys(group, serial_user_keys_writer)
    user_keys_reader = deserialize_user_abe_keys(group, serial_user_keys_reader)

    # Encrypt a message
    message = "This is a secret message."
    # policy_str = get_policy_doc_ins_emp(user_keys_writer)
    # print(f"Encrypting message under policy: {policy_str}")
    policy = '(PATIENT1@PHR)'
    enc_message = ma_abe_service.encrypt(message, policy)
    #
    # # Print the encrypted AES key
    print(f"Encrypted AES key: {enc_message['abe_policy_enc_key']}")
    #
    # # Send the encrypted message to the server
    print("Sending encrypted message to the server...")
    # send_encrypted_message(user_uuid_writer, enc_message, "HEALTH")
    #
    # # Retrieve encrypted messages from the server
    # print("Retrieving encrypted messages...")
    # enc_message_srv, message_type = get_encrypted_message(user_uuid_reader, 9)
    # if enc_message_srv is None:
        # exit("No encrypted messages retrieved from the server.")
    #
    # Decrypt the message
    print(f"User keys writer: {user_keys_writer}")
    decrypted_message = ma_abe_service.decrypt(user_keys_reader, enc_message)
    print(f"Decrypted message: {decrypted_message}")

    # Post representative message
    # rep_id = '16'
    # patient_id = '6'
    # policy = '(DOCTOR@HOSPITAL2)'
    # auth = 'HOSPITAL2'

    # post_rep_message(message, rep_id, patient_id, policy, auth, ma_abe_service)

def login(patients_list, representatives_list):

    valid = False
    uuid, user_type, attr_list = None, None, None
    while not valid:
        # prompt to select login for patient or representative
        print("Select login for patient or representative")
        print("1. Patient")
        print("2. Representative")

        login = input("Enter your choice: ")
        uuid = None
        attr_list = []

        if login == "1":
            valid = True
            user_type = "PATIENT"
            print("Patients list:")
            for id in patients_list['patients']:
                print(f"Patient {id}")
            attr_list.append('PATIENT@PHR')
            uuid = input("Enter patient id: ")
        elif login == "2":
            valid = True
            user_type = "REPRESENTATIVE"
            print("Representatives list:")
            for id in representatives_list:
                print(f"Representative {id}")
                # print attributes
                print(f"\tAttributes:")
                attr_list = []
                for attr in representatives_list[id]:
                    print(f"\t\t{attr}")
                    attr_list.append(attr)
            uuid = input("Enter representative id: ")

    return uuid, user_type, attr_list


def get_user_secret_key(user_uuid, user_type):
    if user_type == "PATIENT":
        serial_user_keys = get_serialized_patient_secret_key(user_uuid)
    elif user_type == "REPRESENTATIVE":
        serial_user_keys = get_serialized_rep_secret_key(user_uuid)
    else:
        exit("User's secret keys could not be obtained.")
    if serial_user_keys is None:
        exit("User's secret keys could not be obtained.")

    user_keys = deserialize_user_abe_keys(group, serial_user_keys)
    return user_keys


def write_phr_message(ma_abe_service, user_uuid):
    print("Insert message in PHR")
    message = input("Enter message: ")
    policy = input("Enter policy: ")
    write_to_uuid = input(f"Enter ID of the user to write to (only the ID of the current user works [{user_uuid}]): ")
    message_type = input("Enter message type (HEALTH or TRAINING): ")
    if message_type not in ["HEALTH", "TRAINING"]:
        print("Invalid message type.")
    # try:
    #     # encrypt message
    #     enc_message = ma_abe_service.encrypt(message, policy)
    # except Exception as e:
    #     print(f"Error encrypting message: {e}")
    #     return False
    try:
        # send encrypted message to server
        return send_message(user_uuid, write_to_uuid, message, message_type, ma_abe_service, policy)

    except Exception as e:
        print(f"Error sending encrypted message: {e}")
        return False


def read_phr_message(ma_abe_service, user_uuid, user_keys):
    message_id = int(input("Enter ID of the message to read: "))
    if message_id < 1:
        print("Invalid message ID.")
        return None
    try:
        enc_message, message_type = get_encrypted_message(user_uuid, int(message_id))
    except Exception as e:
        print(f"Error retrieving encrypted message: {e}")
        return None

    if enc_message is None:
        print("Message not found.")
        return None

    try:
        print(f"User keys: {user_keys}")
        decrypted_message = ma_abe_service.decrypt(user_keys, enc_message)
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

    return decrypted_message


def patient_actions(ma_abe_service, user_uuid, user_keys):
    done = False
    while not done:
        print("Select action")
        print("1. Write PHR message")
        print("2. Read PHR message")
        print("3. Exit")
        action = input("Enter your choice: ")

        if action == "1":
            if write_phr_message(ma_abe_service, user_uuid):
                print("Message written.")
        elif action == "2":
            message = read_phr_message(ma_abe_service, user_uuid, user_keys)
            if message is not None:
                print(f"Message: {message}")
        elif action == "3":
            done = True


def write_phr_message_as_rep(ma_abe_service, rep_uuid, auth):
    message = input("Enter message: ")
    patient_id = input("Enter patient id: ")
    patient_policy = input("Enter the message policy: ")
    return post_rep_message(
        message,
        rep_uuid,
        patient_id,
        patient_policy,
        auth,
        ma_abe_service
    )

def rep_actions(ma_abe_service, user_uuid, user_keys, auth_list):
    done = False
    while not done:
        print("Select action")
        print("1. Write PHR message")
        print("2. Read PHR message")
        print("3. Exit")
        action = input("Enter your choice: ")

        if action == "1":
            print(f"Rep {user_uuid} can act as a representative for the following authorities:")
            for auth in auth_list:
                print(f"\t{auth}")
            auth = input("Enter the authority: ")
            if write_phr_message_as_rep(ma_abe_service, user_uuid, auth):
                print("Message written.")
        elif action == "2":
            message = read_phr_message(ma_abe_service, user_uuid, user_keys)
            if message is not None:
                print(f"Message: {message}")
        elif action == "3":
            done = True


def get_auths_from_uuid(user_uuid, user_type):
    if user_type == "PATIENT":
        return ['PHR']
    elif user_type == "REPRESENTATIVE":
        rep = db_get_rep(user_uuid)
        rep_keys = rep["keys"]["keys"]
        # get attributes from keys
        attributes = list(rep_keys.keys())
        # for each attribute, get the authority
        auth_list = []
        for attr in attributes:
            print(f"Attribute: {attr}")
            auth = attr.split("@")[1]
            auth_list.append(auth)
        return auth_list
    else:
        return []



def main():
    # get list of patients
    patients_list = get_patients_list()
    # get list of representatives
    representatives_list = get_representatives_list()

    while True:

        user_uuid, user_type, usr_attr_list = login(patients_list, representatives_list)
        print(f"Logged with ID {user_uuid} and attributes {usr_attr_list}.")
        public_params, ma_abe_service = init()
        user_keys = get_user_secret_key(user_uuid, user_type)
        auth_list = get_auths_from_uuid(user_uuid, user_type)
        print(f"User keys: {user_keys}")
        if user_type == "PATIENT":
            patient_actions(ma_abe_service, user_uuid, user_keys)
        elif user_type == "REPRESENTATIVE":
            rep_actions(ma_abe_service, user_uuid, user_keys, auth_list)
        else:
            print("Invalid user type.")
            break


if __name__ == '__main__':
    # test()
    main()
