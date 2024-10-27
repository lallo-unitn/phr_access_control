import pickle


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