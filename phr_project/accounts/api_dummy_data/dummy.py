from accounts.services.ma_abe_service import MAABEService

def __get_test_user_attr():
    return ['DOCTOR@HOSPITAL', 'PATIENT@PHR_1']

def __get_test_enc_messages():
    ma_abe_service = MAABEService()

    # String message to encrypt
    message1 = "This is a secret message"
    policy1 = '((PATIENT@PHR_1 or DOCTOR@HOSPITAL))'
    message1_id = "1"

    message2 = "This is another secret message"
    policy2 = '((PATIENT@PHR_2 or DOCTOR@HOSPITAL))'
    message2_id = "2"

    enc_message1 = ma_abe_service.encrypt(message1, policy1)
    enc_message2 = ma_abe_service.encrypt(message2, policy2)

    print(f"enc_message1: {enc_message1}")
    print(f"enc_message2: {enc_message2}")

    abe_policy_enc_key1 = enc_message1['abe_policy_enc_key']
    sym_enc_file1 = enc_message1['sym_enc_file']

    abe_policy_enc_key2 = enc_message2['abe_policy_enc_key']
    sym_enc_file2 = enc_message2['sym_enc_file']

    enc_message1 = {'abe_policy_enc_key': abe_policy_enc_key1, 'sym_enc_file': sym_enc_file1}
    enc_message2 = {'abe_policy_enc_key': abe_policy_enc_key2, 'sym_enc_file': sym_enc_file2}

    messages: dict = {}
    messages[message1_id] = enc_message1
    messages[message2_id] = enc_message2

    return messages