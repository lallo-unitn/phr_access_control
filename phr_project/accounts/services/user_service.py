import json
import random
import base64 as b64

from typing import List, Mapping, Set, Tuple
from xml.etree.ElementTree import Element

from django.http import JsonResponse

from accounts.api_dummy_data.dummy import __get_test_enc_messages
from accounts.services.ma_abe_service import MAABEService

from accounts.models import Message, AesKeyEncWithAbe, Patient, add_patient, add_authority_rep, \
    AuthorityRep, PatientRep, MAABEPublicParams, Authority, PubKey
from accounts.utils.constants import TEST_AUTH_ATTRS, DEFAULT_ABE_PUBLIC_PARAMS_INDEX
from accounts.utils.serial import base64_user_abe_keys, serialize_encrypted_abe_ciphertext

ma_abe = MAABEService()
challenge_map: Mapping[str, Tuple[Element, str, str]] = {}

def patients_are_init():
    # Check if the Patient table is not empty
    return Patient.objects.exists()

def authority_reps_are_init():
    # Check if the AuthorityRep table is not empty
    return AuthorityRep.objects.exists()

def patient_reps_are_init():
    # Check if the PatientRep table is not empty
    return PatientRep.objects.exists()

def __get_patients_attrs_from_db(uuid):
    # Get the user attributes from the Patient table
    user = Patient.objects.get(pk=uuid)
    return user.attributes

def __get_auth_reps_attrs_from_db(uuid):
    # Get the user attributes from the AuthorityRep table
    user = AuthorityRep.objects.get(pk=uuid)
    return user.attributes

def __patients_init(start_id=0, end_id=9):
    # initialize 10 patients
    for i in range(start_id, end_id):
        add_patient(
            patient_id=str(i)
        )

def __auth_reps_init(start_id=10, end_id=19):
    auth_ids = TEST_AUTH_ATTRS.keys()
    # auth_names as list
    auth_ids = list(auth_ids)
    # initialize 10 authority representatives
    for i in range(start_id, end_id):
        auth_id = auth_ids.pop()
        # append to every element in TEST_AUTH_ATTRS[auth_id], str(i)
        auth_attr = []

        for attr in TEST_AUTH_ATTRS[auth_id]:
            auth_attr.append(attr)

        add_authority_rep(
            rep_id=str(i),
            authority_id= auth_id,
            name=str(i),
            rep_type=None,
            attributes=auth_attr
        )

def __assign_auth_reps_to_patients(num_records=20):
    # Get all Patient and AuthorityRep records
    patients = list(Patient.objects.all())
    reps = list(AuthorityRep.objects.all())

    if not patients or not reps:
        print("Ensure there are existing patients and authority representatives before populating.")
        return

    created_records = []

    for _ in range(num_records):
        # Randomly choose a patient and an authority representative
        patient = random.choice(patients)
        rep = random.choice(reps)

        # Check if this patient-rep pair already exists to avoid duplicates
        if not PatientRep.objects.filter(patient=patient, rep=rep).exists():
            patient_rep = PatientRep.objects.create(
                patient=patient,
                rep=rep
            )
            created_records.append(patient_rep)
            print(f"Created PatientRep: Patient ({patient.patient_id}) - Rep ({rep.rep_id})")
        else:
            print(f"Skipped PatientRep: Patient ({patient.patient_id}) - Rep ({rep.rep_id}) already exists")

    return created_records

def get_abe_public_parameters(request):
    ma_abe_service = MAABEService()
    # get parameters from MAABEPublicParams in model
    public_parameters = (
        MAABEPublicParams.objects.get(
            id=DEFAULT_ABE_PUBLIC_PARAMS_INDEX
        )
    )
    b64_serial_public_parameters = {
        'serial_g1': b64.b64encode(public_parameters.g1_serial).decode('utf-8'),
        'serial_g2': b64.b64encode(public_parameters.g2_serial).decode('utf-8'),
        'serial_egg': b64.b64encode(public_parameters.egg_serial).decode('utf-8')
    }
    return JsonResponse(b64_serial_public_parameters)

def get_user_secret_key(request, uuid: str):
    ma_abe_service = MAABEService()

    if not patients_are_init():
        __patients_init()
    if not authority_reps_are_init():
        __auth_reps_init()
    if not patient_reps_are_init():
        __assign_auth_reps_to_patients()

    try:
        user_attrs = __get_patients_attrs_from_db(uuid)
    except Patient.DoesNotExist:
        user_attrs = __get_auth_reps_attrs_from_db(uuid)

    print(f"user_attrs: {user_attrs}")
    user_auth_attrs: Mapping[str, List] = {}

    # iterate on the user attributes
    for user_attr in user_attrs:
        attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
        if attr_auth not in user_auth_attrs:
            user_auth_attrs[attr_auth] = []
        user_auth_attrs[attr_auth].append(user_attr)
        print(f"user_auth_attrs: {user_auth_attrs}")

    user_keys_by_auth: Mapping[str, List] = {}

    for auth, user_attrs in user_auth_attrs.items():
        user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(
            auth=auth,
            user_id=uuid,
            user_attrs=user_attrs
        )

    if len(user_keys_by_auth.keys()) >= 2:
        user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
        print(f"%%%%%%%%%%%user_keys: {user_keys}")
    else:
        temp_user_keys = list(user_keys_by_auth.values())
        user_keys = temp_user_keys.pop()
        print(f"-------------user_keys: {user_keys}")

    # user_abe_keys = {'GID': uuid, 'keys': user_keys}

    # message = "This is a secret message"
    # policy = 'PATIENT@PHR_0'

    # enc_message = ma_abe_service.encrypt(message, policy)
    # dec_message = ma_abe_service.decrypt(user_abe_keys, enc_message)

    # print(f"Decrypted message: {dec_message}")

    # print(f"user_keys: {user_keys}")
    serial_keys = base64_user_abe_keys(ma_abe_service.helper.get_pairing_group(), user_keys)
    user_abe_keys = {'GID': uuid, 'keys': serial_keys}
    # print(f"user_abe_keys: {user_abe_keys}")

    return JsonResponse(user_abe_keys)

def test_get_user_secret_key(request, uuid: str):
    ma_abe_service = MAABEService()

    if not patients_are_init():
        __patients_init()
    if not authority_reps_are_init():
        __auth_reps_init()
    if not patient_reps_are_init():
        __assign_auth_reps_to_patients()

    user_attrs = __get_patients_attrs_from_db(uuid)
    print(f"user_attrs: {user_attrs}")
    user_auth_attrs: Mapping[str, List] = {}

    # iterate on the user attributes
    for user_attr in user_attrs:
        attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
        if attr_auth not in user_auth_attrs:
            user_auth_attrs[attr_auth] = []
        user_auth_attrs[attr_auth].append(user_attr)
        print(f"user_auth_attrs: {user_auth_attrs}")

    user_keys_by_auth: Mapping[str, List] = {}

    for auth, user_attrs in user_auth_attrs.items():
        user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(
            auth=auth,
            user_id=uuid,
            user_attrs=user_attrs
        )

    if len(user_keys_by_auth.keys()) >= 2:
        user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
        print(f"%%%%%%%%%%%user_keys: {user_keys}")
    else:
        temp_user_keys = list(user_keys_by_auth.values())
        user_keys = temp_user_keys.pop()
        print(f"-------------user_keys: {user_keys}")

    user_abe_keys = {'GID': uuid, 'keys': user_keys}

    return user_abe_keys

def get_message_aes_key(request, uuid, message_id = None):
    messages: dict = __get_test_enc_messages()
    enc_aes_keys: dict = {}

    for message_id, enc_message in messages.items():
        enc_aes_keys[message_id] = enc_message['abe_policy_enc_key']
        # print(f"enc_aes_keys: {enc_aes_keys}")

    return JsonResponse(enc_aes_keys)

def post_message_aes_key(request, uuid, message_id = None):
    try:
        # Parse JSON data from the request body
        data = json.loads(request.body)
        # Validate required fields
        if 'c_serial' not in data:
            return JsonResponse({"error": "Missing 'c_serial' field"}, status=400)

        encoded_aes_key = data['c_serial']
        decoded_aes_key = b64.b64decode(encoded_aes_key)

        # Create AesKeyEncWithAbe instance
        aes_key_enc_with_abe = AesKeyEncWithAbe(
            c_serial=decoded_aes_key
        )
        # Save the instance to the database
        aes_key_enc_with_abe.save()
        # Return success response with the created ID
        return JsonResponse({"message": "AesKeyEncWithAbe created", "id": aes_key_enc_with_abe.id}, status=201)

    except json.JSONDecodeError:
        # Handle JSON parsing error
        return JsonResponse({"error": "Invalid JSON"}, status=400)

def put_message_aes_key(request, uuid, message_id = None):
    try:
        # Find the message by its ID
        try:
            message = Message.objects.get(pk=message_id)
        except Message.DoesNotExist:
            return JsonResponse({"error": "Message not found"}, status=404)

        # Parse JSON data from the request body
        data = json.loads(request.body)

        # Update fields based on provided data
        if 'aes_enc_message' in data:
            message.aes_enc_message = data['aes_enc_message']
        if 'message_type' in data:
            if data['message_type'] in dict(Message.MESSAGE_TYPE_CHOICES):
                message.message_type = data['message_type']
            else:
                return JsonResponse({"error": "Invalid message type"}, status=400)
        if 'aes_key_enc_with_abe' in data:
            try:
                aes_key = AesKeyEncWithAbe.objects.get(pk=data['aes_key_enc_with_abe'])
                message.aes_key_enc_with_abe = aes_key
            except AesKeyEncWithAbe.DoesNotExist:
                return JsonResponse({"error": "AesKeyEncWithAbe not found"}, status=404)

        # Save the updated message
        message.save()

        return JsonResponse({"message": "Message updated successfully"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


def get_policy_doc_ins_emp(request, uuid):
    # Get user's reps
    user_reps = PatientRep.objects.filter(patient=uuid)
    rep_attr_list: Mapping[str, List] = {}
    all_attrs = []

    for rep in user_reps:
        # Get the attributes list
        attributes = rep.rep.attributes
        rep_id_str = str(rep.rep_id)
        # Concatenate rep_id to each attribute string but only if attribute does not contain "HEALTHCLUB"
        rep_attr_list[rep_id_str] = [f"{attr}@{rep_id_str}" for attr in attributes if "HEALTHCLUB" not in attr]

    # Collect all attributes into a single list
    for attr_list in rep_attr_list.values():
        all_attrs.extend(attr_list)

    # get patient by id
    patient = Patient.objects.get(pk=uuid)
    # get patient attributes
    patient_attrs = patient.attributes
    all_attrs.extend(patient_attrs)

    # Join all attributes with ' AND ' and enclose in parentheses
    policy = "(" + " OR ".join(all_attrs) + ")"

    # return json response
    return JsonResponse({"policy": policy}, status=200)


def get_user_message(request, uuid: str, message_id: int):
    # Get the message by its ID
    try:
        message = Message.objects.get(message_id=message_id)
        aes_key_enc_with_abe = message.aes_key_enc_with_abe
        b64_serial_aes_key = b64.b64encode(aes_key_enc_with_abe.c_serial).decode('utf-8')
        b64_serial_enc_message = b64.b64encode(message.aes_enc_message).decode('utf-8')
        message_data = {
            'b64_serial_abe_policy_enc_key': b64_serial_aes_key,
            'b64_serial_enc_message': b64_serial_enc_message,
            'message_type': message.message_type
        }
        return JsonResponse(message_data)
    except Message.DoesNotExist:
        return JsonResponse({"error": "Message not found"}, status=404)


def post_user_message(request, uuid):
    # data = {
    #         'b64_serial_abe_policy_enc_key': b64_serial_abe_policy_enc_key,
    #         'b64_serial_enc_message': b64_serial_enc_message,
    #         'message_type': type
    #     }
    try:
        # Parse JSON data from the request body
        data = json.loads(request.body)
        # Validate required fields
        if 'b64_serial_abe_policy_enc_key' not in data:
            return JsonResponse({"error": "Missing 'b64_serial_abe_policy_enc_key' field"}, status=400)
        if 'b64_serial_enc_message' not in data:
            return JsonResponse({"error": "Missing 'b64_serial_enc_message' field"}, status=400)
        if 'message_type' not in data:
            return JsonResponse({"error": "Missing 'message_type' field"}, status=400)

        encoded_aes_key = data['b64_serial_abe_policy_enc_key']
        decoded_aes_key = b64.b64decode(encoded_aes_key)

        encoded_enc_message = data['b64_serial_enc_message']
        decoded_enc_message = b64.b64decode(encoded_enc_message)

        # Create AesKeyEncWithAbe instance
        aes_key_enc_with_abe = AesKeyEncWithAbe(
            c_serial=decoded_aes_key
        )
        # Save the instance to the database
        aes_key_enc_with_abe.save()

        # Create Message instance
        message = Message(
            aes_enc_message=decoded_enc_message,
            message_type=data['message_type'],
            aes_key_enc_with_abe=aes_key_enc_with_abe,
            patient_id=uuid
        )
        # Save the instance to the database
        message.save()
        # Return success response with the created ID
        return JsonResponse({"message": "Message created", "id": message.message_id}, status=201)

    except json.JSONDecodeError:
        # Handle JSON parsing error
        return JsonResponse({"error": "Invalid JSON"}, status=400)


def put_user_message(request, uuid):
    return None

def get_auth_public_key(request, auth_id):
    pub_key_id = Authority.objects.get(id=auth_id).pub_key_id
    pub_key = PubKey.objects.get(id=pub_key_id)
    b64_serial_pub_key = {
        'b64_serial_public_key_egga': b64.b64encode(pub_key.egga_serial).decode('utf-8'),
        'b64_serial_public_key_gy': b64.b64encode(pub_key.gy_serial).decode('utf-8')
    }
    return JsonResponse(b64_serial_pub_key)


def get_challenge_auth_patient(request, rep_id:str, uuid: str, type:str):
    # get patient hospitals
    patient_rep = PatientRep.objects.filter(patient=uuid)
    hospitals_set = set()

    check_auth = ""
    check_attr = ""

    if type == "HEALTH":
        check_auth = "HOSPITAL"
        check_attr = "DOCTOR"
    elif type == "TRAINING":
        check_auth = "HEALTHCLUB"
        check_attr = "HEALTHCLUBTRAINER"

    for rep in patient_rep:
        authority_id = rep.rep.authority_id
        if check_auth in authority_id:
            hospitals_set.add(authority_id)

    if not hospitals_set:
        return JsonResponse({"error": "Patient has no hospitals"}, status=400)

    # Generate a random challenge
    challenge = ma_abe.helper.get_random_group_element()
    challenge_map[rep_id] = (challenge, uuid, type)
    policy = "("
    for hospital in hospitals_set:
        policy += f"{check_attr}@{hospital} OR "
    policy = policy[:-4] + ")"
    encrypted_challenge = ma_abe.helper.encrypt(challenge, policy)

    # serialize challenge
    serial_challenge = serialize_encrypted_abe_ciphertext(encrypted_challenge, ma_abe.group)
    # encode challenge
    b64_serial_challenge = b64.b64encode(serial_challenge).decode('utf-8')

    return JsonResponse({"b64_serial_challenge": b64_serial_challenge})

def post_challenge_auth_patient(request, rep_id: str, uuid: str, type:str):
    # parse JSON data from the request body
    # data = {
    #         'b64_serial_challenge': b64_serial_challenge,
    #         'b64_serial_hospital_message': b64_serial_hospital_message
    #     }
    try:
        data = json.loads(request.body)
        # validate required fields
        if 'b64_serial_challenge' not in data and 'b64_serial_hospital_message' not in data:
            return JsonResponse({"error": "Missing 'b64_serial_challenge' field"}, status=400)

        b64_serial_challenge = data['b64_serial_challenge']
        serial_challenge = b64.b64decode(b64_serial_challenge)

        # deserialize challenge
        challenge = ma_abe.group.deserialize(serial_challenge)
        print(f"Challenge: {challenge}")

        if rep_id not in challenge_map:
            # reset challenge
            challenge_map[rep_id] = None
            return JsonResponse({"error": "Challenge failed"}, status=403)

        if (
                challenge_map[rep_id][0] != challenge
                or challenge_map[rep_id][1] != uuid
                or challenge_map[rep_id][2] != type
        ):
            print(f"Challenge: {challenge}")
            print(f"Challenge_map: {challenge_map[rep_id]}")
            print(f"Challenge_map[0]: {challenge_map[rep_id][0]}")
            print(f"Challenge_map[1]: {challenge_map[rep_id][1]}")
            print(f"rep_id: {uuid}")
            print(f"Challenge_map[2]: {challenge_map[rep_id][2]}")
            print(f"type: {type}")
            # reset challenge
            challenge_map[rep_id] = None
            return JsonResponse({"&&error": "Challenge failed"}, status=403)

        b64_serial_hospital_message = data['b64_serial_rep_message']

        encoded_aes_key = b64_serial_hospital_message['b64_serial_abe_policy_enc_key']
        decoded_aes_key = b64.b64decode(encoded_aes_key)

        encoded_enc_message = b64_serial_hospital_message['b64_serial_enc_message']
        decoded_enc_message = b64.b64decode(encoded_enc_message)

        # Create AesKeyEncWithAbe instance
        aes_key_enc_with_abe = AesKeyEncWithAbe(
            c_serial=decoded_aes_key
        )
        # Save the instance to the database
        aes_key_enc_with_abe.save()

        # Create Message instance
        message = Message(
            aes_enc_message=decoded_enc_message,
            message_type=b64_serial_hospital_message['message_type'],
            aes_key_enc_with_abe=aes_key_enc_with_abe,
            patient_id=uuid
        )

        # reset challenge
        challenge_map[rep_id] = None

        # Save the instance to the database
        message.save()

        return JsonResponse({"message": "Challenge solved"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


# def __get_patient_hospitals(uuid):
#     # get patients doctors
#     patient_rep = PatientRep.objects.filter(patient=uuid)
#     # get rep attributes
#     attr_set = set()
#     for rep in patient_rep:
#         for attr in rep.rep.attributes:
#             print(f"rep_id_str: {attr}")
#             if "DOCTOR" in attr:
#                 attr_set.add(attr)
#
#     # print all elements in the set
#     for element in attr_set:
#         print(element)
#
#     # for every element in the set, get what is after the @
#     hospitals = set()
#     for element in attr_set:
#         attr, auth, id = ma_abe.helper.unpack_attribute(element)
#         hospitals.add(auth)
#
#     return hospitals
#
#
# def __doctor_in_patient_doctors(doctor_attr: List[str], patient_doctors: Set[str]):
#     # Get what is after the '@' and before the '_' in the doctor attributes
#     doctor_hospitals = set()
#
#     for element in doctor_attr:
#         attr, auth, id = ma_abe.helper.unpack_attribute(element)
#         # Normalize by stripping whitespace and converting to lowercase
#         doctor_hospitals.add(auth.strip().lower())
#
#     # Normalize patient_doctors by stripping whitespace and converting to lowercase
#     normalized_patient_doctors = {hospital.strip().lower() for hospital in patient_doctors}
#
#     print("Doctor hospitals:")
#     for element in doctor_hospitals:
#         print(element)
#
#     print("Patient hospitals:")
#     for element in normalized_patient_doctors:
#         print(element)
#
#     # Check if there are any matches between doctor_hospitals and patient_doctors
#     return not doctor_hospitals.isdisjoint(normalized_patient_doctors)