import hashlib

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

from ma_abe.migrations.utils.charm_helpers import CharmMAABEHelper


class MAABEService:
    def __init__(self):
        self.helper = CharmMAABEHelper()
        self._initialize_session_key()
        # map session keys to policy
        self.session_keys = {}

    # Generate the public key and master keys
    def _initialize_session_key(self):
        session_key = self.helper.generate_session_key()
        return session_key

    # Derive a symmetric key from the session key
    def get_symmetric_key(self, session_key):
        session_key_bytes = self.helper.get_pairing_group().serialize(session_key)
        sym_key = hashlib.sha256(session_key_bytes).digest()
        return SymmetricCryptoAbstraction(sym_key)

    # Encrypt the session key using the ABE scheme
    def get_abe_encrypted_session_key(self, policy, session_key):
        # if policy is not in the form %s@%s then throw an error
        if '@' not in policy:
            raise ValueError('Invalid policy format')
        enc_session_key = self.helper.encrypt(policy, session_key)
        self.session_keys[policy] = enc_session_key

    # Encrypt the file using the symmetric key and
    # return the encrypted file and the ABE encrypted session key
    def encrypt_msg(self, file, policy, session_key):
        sym_key = self.get_symmetric_key(session_key)
        abe_enc_session_key = self.get_abe_encrypted_session_key(session_key, policy)
        sym_enc_file = sym_key.encrypt(file)
        return {'abe_enc_session_key': abe_enc_session_key, 'sym_enc_file': sym_enc_file}

