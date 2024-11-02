import pickle

from charm.core.math.pairing import G2
import base64 as b64


def deserialize_encrypted_aes_key(pickled_data, group):
    # Unpickle the data to retrieve the original dictionary structure
    data = pickle.loads(pickled_data)
    # Convert bytes back to group elements using group.deserialize
    data['C0'] = group.deserialize(data['C0'])
    data['C1'] = {k: group.deserialize(v) for k, v in data['C1'].items()}
    data['C2'] = {k: group.deserialize(v) for k, v in data['C2'].items()}
    data['C3'] = {k: group.deserialize(v) for k, v in data['C3'].items()}
    data['C4'] = {k: group.deserialize(v) for k, v in data['C4'].items()}

    return data


def serialize_encrypted_aes_key(encrypted_data, group):
    # Convert group elements to bytes and then pickle the entire data structure
    serialized_data = {
        'policy': encrypted_data['policy'],
        'C0': group.serialize(encrypted_data['C0']),
        'C1': {k: group.serialize(v) for k, v in encrypted_data['C1'].items()},
        'C2': {k: group.serialize(v) for k, v in encrypted_data['C2'].items()},
        'C3': {k: group.serialize(v) for k, v in encrypted_data['C3'].items()},
        'C4': {k: group.serialize(v) for k, v in encrypted_data['C4'].items()}
    }
    # Pickle the dictionary into a binary format
    return pickle.dumps(serialized_data)


def serialize_encrypted_data(enc_data):
    # Pickle the dictionary into a binary format
    return pickle.dumps(enc_data)


def deserialize_encrypted_data(pickled_data):
    # Unpickle the data to retrieve the original dictionary structure
    return pickle.loads(pickled_data)

def serialize_ma_abe_public_parameters(group, public_parameters):
    serial_g1:bytearray = group.serialize(public_parameters['g1'])
    serial_g2:bytearray = group.serialize(public_parameters['g2'])
    serial_egg:bytearray = group.serialize(public_parameters['egg'])
    return {
        'serial_g1': serial_g1,
        'serial_g2': serial_g2,
        'serial_egg': serial_egg
    }

def deserialize_ma_abe_public_parameters(group, serial_params):
    g1 = group.deserialize(serial_params['serial_g1'])
    g2 = group.deserialize(serial_params['serial_g2'])
    egg = group.deserialize(serial_params['serial_egg'])
    H = lambda x: group.hash(x, G2)
    F = lambda x: group.hash(x, G2)
    return {
        'g1': g1,
        'g2': g2,
        'egg': egg,
        'H': H,
        'F': F
    }

def serialize_auth_key_pair(group, auth_name, public_key, secret_key):
    serial_public_key_egga = group.serialize(public_key['egga'])
    serial_public_key_gy = group.serialize(public_key['gy'])

    serial_secret_key_alpha = group.serialize(secret_key['alpha'])
    serial_secret_key_y = group.serialize(secret_key['y'])
    return {
        'auth_name': auth_name,
        'serial_public_key_egga': serial_public_key_egga,
        'serial_public_key_gy': serial_public_key_gy,
        'serial_secret_key_alpha': serial_secret_key_alpha,
        'serial_secret_key_y': serial_secret_key_y
    }

def deserialize_auth_key_pair(group, serial_key_pair):

    public_key: dict = {
        'name': serial_key_pair['auth_name'],
        'egga': group.deserialize(serial_key_pair['serial_public_key_egga']),
        'gy': group.deserialize(serial_key_pair['serial_public_key_gy'])
    }

    secret_key: dict = {
        'name': serial_key_pair['auth_name'],
        'alpha': group.deserialize(serial_key_pair['serial_secret_key_alpha']),
        'y': group.deserialize(serial_key_pair['serial_secret_key_y'])
    }

    return {
        'public_key': public_key,
        'secret_key': secret_key
    }

def base64_user_abe_keys(group, user_keys):
    serial_user_keys: dict = {}
    for key, value in user_keys.items():
        k = value.get('K')
        kp = value.get('KP')
        k_and_kp = {
            'K': b64.b64encode(group.serialize(k)).decode('utf-8'),
            'KP': b64.b64encode(group.serialize(kp)).decode('utf-8')
        }
        user_key = { key: k_and_kp }
        serial_user_keys.update(user_key)
    return serial_user_keys

def deserialize_user_abe_keys(group, serialized_user_keys):
    deserial_user_keys: dict = {}
    for key, value in serialized_user_keys.items():
        k_serialized = value.get('K')
        kp_serialized = value.get('KP')

        # Decode from base64 and deserialize using the group
        k = group.deserialize(b64.b64decode(k_serialized))
        kp = group.deserialize(b64.b64decode(kp_serialized))

        # Store the deserialized keys
        deserial_user_keys[key] = {
            'K': k,
            'KP': kp
        }

    return deserial_user_keys

def deserialize_auth_public_key(group, serialized_auth_public_key):
    b64_serial_public_key_egga = serialized_auth_public_key['b64_serial_public_key_egga']
    b64_serial_public_key_gy = serialized_auth_public_key['b64_serial_public_key_gy']

    # Decode from base64 and deserialize using the group
    public_key_egga = group.deserialize(b64.b64decode(b64_serial_public_key_egga))
    public_key_gy = group.deserialize(b64.b64decode(b64_serial_public_key_gy))

    # Store the deserialized keys
    deserial_public_key = {
        'egga': public_key_egga,
        'gy': public_key_gy
    }

    print(f"deserial_public_key: {deserial_public_key}")

    return deserial_public_key