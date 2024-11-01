import json
import base64 as b64
import random
from typing import List, Mapping

from django.http import JsonResponse

from accounts.api_dummy_data.dummy import __get_test_enc_messages
from accounts.services.ma_abe_service import MAABEService

from accounts.models import Message, AesKeyEncWithAbe, Patient, add_patient, add_authority_rep, \
    AuthorityRep, PatientRep
from accounts.utils.constants import TEST_AUTH_ATTRS
from accounts.utils.serial import base64_user_abe_keys


def users_are_init():
    # Check if the Patient table is not empty
    return Patient.objects.exists()

def __get_user_attrs_from_db(uuid):
    # Get the user attributes from the Patient table
    user = Patient.objects.get(pk=uuid)
    return user.attributes

def __users_init():
    # Initialize 10 patients
    __patients_init()
    # Initialize 10 authority representatives
    __auth_reps_init()
    # Assign auth_reps to patients
    __assign_auth_reps_to_patients()

def __patients_init(start_id=0, end_id=9):
    # initialize 10 patients
    for i in range(start_id, end_id):
        add_patient(
            patient_id=str(i),
        )

def __auth_reps_init(start_id=10, end_id=19):
    auth_ids = TEST_AUTH_ATTRS.keys()
    # auth_names as list
    auth_ids = list(auth_ids)
    # initialize 10 authority representatives
    for i in range(start_id, end_id):
        auth_id = auth_ids.pop()
        add_authority_rep(
            rep_id=str(i),
            authority_id= auth_id,
            name=str(i),
            rep_type=None,
            attributes=TEST_AUTH_ATTRS[auth_id]
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

def get_user_secret_key(request, uuid: str):
    ma_abe_service = MAABEService()

    if not users_are_init():
        __users_init()

    user_attrs = __get_user_attrs_from_db(uuid)

    user_auth_attrs: Mapping[str, List] = {}

    # iterate on the user attributes
    for user_attr in user_attrs:
        attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
        if attr_auth not in user_auth_attrs:
            user_auth_attrs[attr_auth] = []
        user_auth_attrs[attr_auth].append(user_attr)

    user_keys_by_auth: Mapping[str, List] = {}

    for auth, user_attrs in user_auth_attrs.items():
        user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(
            auth=auth,
            user_id=uuid,
            user_attrs=user_attrs
        )
    if len(user_keys_by_auth.keys()) >= 2:
        user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
    else:
        user_keys = user_keys_by_auth[list(user_keys_by_auth.keys())[0]]
        print(f"user_keys: {user_keys}")
    serial_keys = base64_user_abe_keys(ma_abe_service.helper.get_pairing_group(), user_keys)
    user_abe_keys = {'GID': uuid, 'serial_keys': serial_keys}
    # print(f"user_abe_keys: {user_abe_keys}")
    # print(f"serialized keys: {serial_keys}")

    return JsonResponse(user_abe_keys)

def get_message_aes_key(request, uuid, message_id = None):
    messages: dict = __get_test_enc_messages()
    enc_aes_keys: dict = {}

    for message_id, enc_message in messages.items():
        enc_aes_keys[message_id] = enc_message['abe_policy_enc_key']
        print(f"enc_aes_keys: {enc_aes_keys}")

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

def get_user_message(request, uuid: str):
    messages: dict = __get_test_enc_messages()
    enc_record: dict = {}

    for message_id, enc_message in messages.items():
        enc_record[message_id] = enc_message['sym_enc_file']

    return JsonResponse(enc_record)

def post_user_message(request, uuid):
    return None


def put_user_message(request, uuid):
    return None