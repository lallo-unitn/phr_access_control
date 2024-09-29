from charm.core.math.pairing import GT
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.toolbox.pairinggroup import PairingGroup


class DabeExample():
    def __init__(self):
        group = PairingGroup('SS512')
        dabe = Dabe(group)
        public_parameters = dabe.setup()
        auth_attrs_1 = ['ONE', 'TWO', 'THREE', 'FOUR']
        auth_attrs_2 = ['ONE', 'FOUR', 'SEVEN', 'EIGHT']
        (master_secret_key_1, master_public_key_1) = dabe.authsetup(public_parameters, auth_attrs_1)
        (master_secret_key_2, master_public_key_2) = dabe.authsetup(public_parameters, auth_attrs_2)

        # generate a key for a user
        ID_1, secret_keys_1 = "bob", {}
        usr_attrs_1 = ['THREE', 'ONE', 'TWO']
        for i in usr_attrs_1:  dabe.keygen(public_parameters, master_secret_key_1, i, ID_1, secret_keys_1)

        # generate a key for a second user
        ID_2, secret_keys_2 = "alice", {}
        usr_attrs_2 = ['ONE', 'SEVEN']
        for i in usr_attrs_2:  dabe.keygen(public_parameters, master_secret_key_2, i, ID_2, secret_keys_2)

        msg = group.random(GT)
        print("Message: ", msg)

        policy = '((ONE or THREE) and (TWO or FOUR))'
        # encrypt the message
        cipher_text = dabe.encrypt(public_parameters, master_public_key_1, msg, policy)
        print("Cipher Text: ", cipher_text)
        # decrypt the message
        rec_msg_1 = dabe.decrypt(public_parameters, secret_keys_1, cipher_text)
        assert msg == rec_msg_1, "FAILED Decryption: message is incorrect"
        print("Successful Decryption!!!")

        #handle exceptions
        try:
            rec_msg_2 = dabe.decrypt(public_parameters, secret_keys_2, cipher_text)
            print("Successful Decryption!!!")
        except Exception as e:
            print("FAILED Decryption: message is incorrect")
            print(e)

if __name__ == "__main__":
    DabeExample()