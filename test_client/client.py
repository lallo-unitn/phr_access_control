import requests
import json
import base64
import hashlib
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject

# Initialize the pairing group and MAABE scheme
group = PairingGroup('SS512')
maabe = MaabeRW15(group)

# Define server URL
SERVER_URL = 'http://localhost:8000'  # Change this to your server's URL

def get_user_secret_key(user_uuid):
    """
    Obtain the user's secret key from the server.
    """
    url = f"{SERVER_URL}/user_secret_key/{user_uuid}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        # Deserialize the keys
        serial_keys = data['serial_keys']
        user_keys = {}

        for attr, keys in serial_keys.items():
            k_serialized = base64.b64decode(keys['K'])
            kp_serialized = base64.b64decode(keys['KP'])

            k = bytesToObject(k_serialized, group)
            kp = bytesToObject(kp_serialized, group)

            user_keys[attr] = {'K': k, 'KP': kp}

        return user_keys
    else:
        print(f"Error fetching user secret key: {response.text}")
        return None

def encrypt_message(message, policy_str):
    """
    Encrypt the message under the given policy.
    """
    # Generate a random AES key
    aes_key = group.random()
    aes_key_bytes = group.serialize(aes_key)

    # Encrypt the AES key using MAABE
    abe_ciphertext = maabe.encrypt(pk_global, pk_auths, aes_key, policy_str)

    # Serialize and encode the ABE ciphertext
    abe_ciphertext_serialized = objectToBytes(abe_ciphertext, group)
    abe_ciphertext_encoded = base64.b64encode(abe_ciphertext_serialized).decode('utf-8')

    # Encrypt the message using the AES key
    aes_cipher = SymmetricCryptoAbstraction(hashlib.sha256(aes_key_bytes).digest())
    encrypted_message = aes_cipher.encrypt(message.encode('utf-8'))

    # Encode the encrypted message
    encrypted_message_encoded = base64.b64encode(encrypted_message).decode('utf-8')

    return abe_ciphertext_encoded, encrypted_message_encoded

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

def decrypt_message(user_keys, abe_ciphertext_encoded, encrypted_message_encoded):
    """
    Decrypt the encrypted message using the user's secret keys.
    """
    # Decode and deserialize the ABE ciphertext
    abe_ciphertext_serialized = base64.b64decode(abe_ciphertext_encoded)
    abe_ciphertext = bytesToObject(abe_ciphertext_serialized, group)

    # Merge user keys for decryption
    user_secret_keys = {}
    for attr, keys in user_keys.items():
        user_secret_keys[attr] = keys

    # Decrypt the AES key using MAABE
    decrypted_aes_key = maabe.decrypt(pk_global, user_secret_keys, abe_ciphertext)
    aes_key_bytes = group.serialize(decrypted_aes_key)

    # Decrypt the message using the AES key
    encrypted_message = base64.b64decode(encrypted_message_encoded)
    aes_cipher = SymmetricCryptoAbstraction(hashlib.sha256(aes_key_bytes).digest())
    decrypted_message = aes_cipher.decrypt(encrypted_message)

    return decrypted_message.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # User UUID
    user_uuid = '0'  # Replace with the actual UUID

    # Obtain user's secret keys
    print("Fetching user's secret keys...")
    user_keys = get_user_secret_key(user_uuid)
    if user_keys is None:
        exit()

    # Retrieve public parameters from the server or initialize them
    # For this example, we'll assume pk_global and pk_auths are obtained somehow
    # You need to fetch or initialize pk_global and pk_auths accordingly
    # For demonstration, we're initializing them here (Replace with actual fetching logic)
    print("Initializing public parameters...")
    pk_global = {}  # Replace with actual global public key
    pk_auths = {}   # Replace with actual authority public keys

    # Encrypt a message
    message = "This is a secret message."
    policy_str = '((PATIENT@PHR_1 or DOCTOR@HOSPITAL))'
    print(f"Encrypting message under policy: {policy_str}")
    abe_ciphertext_encoded, encrypted_message_encoded = encrypt_message(message, policy_str)

    # Send the encrypted message to the server
    print("Sending encrypted message to the server...")
    send_encrypted_message(user_uuid, abe_ciphertext_encoded, encrypted_message_encoded)

    # Retrieve encrypted messages from the server
    print("Retrieving encrypted messages...")
    messages = get_encrypted_messages(user_uuid)
    if messages is None:
        exit()

    # Decrypt messages
    print("Decrypting messages...")
    for message_id, data in messages.items():
        abe_ciphertext_encoded = data['c_serial']
        encrypted_message_encoded = data['aes_enc_message']
        decrypted_message = decrypt_message(user_keys, abe_ciphertext_encoded, encrypted_message_encoded)
        print(f"Decrypted Message [{message_id}]: {decrypted_message}")
