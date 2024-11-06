import json
import random
import base64 as b64

from typing import List, Mapping, Tuple, Set
from xml.etree.ElementTree import Element

from django.http import JsonResponse

from accounts.services.ma_abe_service import MAABEService

from accounts.models import (
    Message, AesKeyEncWithAbe, Patient, add_patient, add_authority_rep,
    AuthorityRep, PatientRep, MAABEPublicParams, Authority, PubKey
)
from accounts.utils.constants import TEST_AUTH_ATTRS, DEFAULT_ABE_PUBLIC_PARAMS_INDEX, NUMBER_OF_REPS, \
    ATTRIBUTES_PER_REP, NUMBER_OF_USERS
from accounts.utils.serial import base64_user_abe_keys, serialize_encrypted_abe_ciphertext


# A mapping to store challenges for authentication
challenge_map: Mapping[str, Tuple[Element, str, str]] = {}

def patients_are_init():
    """Check if the Patient table is not empty."""
    return Patient.objects.exists()

def authority_reps_are_init():
    """Check if the AuthorityRep table is not empty."""
    return AuthorityRep.objects.exists()

def patient_reps_are_init():
    """Check if the PatientRep table is not empty."""
    return PatientRep.objects.exists()

def __get_patients_attrs_from_db(uuid):
    """Retrieve patient attributes from the database using the patient's UUID."""
    user = Patient.objects.get(pk=uuid)
    return user.attributes

def __get_auth_reps_attrs_from_db(uuid):
    """Retrieve authority representative attributes from the database using the rep's UUID."""
    user = AuthorityRep.objects.get(pk=uuid)
    return user.attributes

def __patients_init():
    """Initialize patients in the database with IDs from 0 to number_of_users."""
    for i in range(NUMBER_OF_USERS):
        add_patient(
            patient_id=str(i)
        )


def __auth_reps_init():
    auth_ids = list(TEST_AUTH_ATTRS.keys())
    # Remove 'PHR' from the list of authority IDs
    auth_ids.remove("PHR")

    for i in range(NUMBER_OF_REPS):
        # Initialize a set to store unique attributes
        auth_attr_set: Set[str] = set()

        while len(auth_attr_set) < ATTRIBUTES_PER_REP:
            # Randomly select an authority ID
            auth_id = random.choice(auth_ids)
            # Randomly select an attribute from the selected authority
            attr = random.choice(TEST_AUTH_ATTRS[auth_id])
            auth_attr_set.add(attr)

        # Add the representative to the database
        add_authority_rep(
            name=f"test_name_{i}",
            attributes=list(auth_attr_set)
        )

def __assign_auth_reps_to_patients():
    """Assign authority representatives to patients randomly."""
    # Get all Patient and AuthorityRep records
    patients = list(Patient.objects.all())
    reps = list(AuthorityRep.objects.all())

    if not patients or not reps:
        print("Ensure there are existing patients and authority representatives before populating.")
        return

    created_records = []

    for _ in range(NUMBER_OF_REPS):
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
    """Retrieve the ABE public parameters and return them as a JSON response."""
    ma_abe_service = MAABEService()
    # Get parameters from MAABEPublicParams in the model
    public_parameters = MAABEPublicParams.objects.get(
        id=DEFAULT_ABE_PUBLIC_PARAMS_INDEX
    )
    b64_serial_public_parameters = {
        'serial_g1': b64.b64encode(public_parameters.g1_serial).decode('utf-8'),
        'serial_g2': b64.b64encode(public_parameters.g2_serial).decode('utf-8'),
        'serial_egg': b64.b64encode(public_parameters.egg_serial).decode('utf-8')
    }
    return JsonResponse(b64_serial_public_parameters)

def get_patient_secret_key(request, uuid: str, is_rep: bool):
    """
    Generate and return the user's secret key based on their attributes.

    Initializes data if necessary, retrieves user attributes, generates user keys,
    and returns them in a JSON response.
    """
    ma_abe_service = MAABEService()

    # Retrieve user attributes
    if is_rep:
        user_attrs = __get_auth_reps_attrs_from_db(uuid)
    else:
        user_attrs = __get_patients_attrs_from_db(uuid)

    print(f"user_attrs: {user_attrs}")
    user_auth_attrs: Mapping[str, List] = {}

    # Organize attributes by authority
    for user_attr in user_attrs:
        attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
        if attr_auth not in user_auth_attrs:
            user_auth_attrs[attr_auth] = []
        user_auth_attrs[attr_auth].append(user_attr)
        print(f"user_auth_attrs: {user_auth_attrs}")

    user_keys_by_auth: Mapping[str, List] = {}

    # Generate user keys per authority
    for auth, user_attrs in user_auth_attrs.items():
        user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(
            auth=auth,
            user_id=uuid,
            user_attrs=user_attrs
        )

    # Merge keys from different authorities
    if len(user_keys_by_auth.keys()) >= 2:
        user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())
        print(f"%%%%%%%%%%%user_keys: {user_keys}")
    else:
        temp_user_keys = list(user_keys_by_auth.values())
        user_keys = temp_user_keys.pop()
        print(f"-------------user_keys: {user_keys}")

    serial_keys = base64_user_abe_keys(ma_abe_service.helper.get_pairing_group(), user_keys)
    user_abe_keys = {'GID': uuid, 'keys': serial_keys}

    return JsonResponse(user_abe_keys)

def post_message_aes_key(request, uuid, message_id=None):
    """
    Create a new AES key encrypted with ABE and store it in the database.

    Expects 'c_serial' in the request body.
    """
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

def put_message_aes_key(request, uuid, message_id=None):
    """
    Update an existing message's AES key or other fields.

    Expects 'aes_enc_message', 'message_type', or 'aes_key_enc_with_abe' in the request body.
    """
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
    """
    Generate and return a policy string based on the user's representatives.

    Excludes attributes containing "HEALTHCLUB".
    """
    # Get user's representatives
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

    # Get patient by id
    patient = Patient.objects.get(pk=uuid)
    # Get patient attributes
    patient_attrs = patient.attributes
    all_attrs.extend(patient_attrs)

    # Join all attributes with ' OR ' and enclose in parentheses
    policy = "(" + " OR ".join(all_attrs) + ")"

    # Return JSON response
    return JsonResponse({"policy": policy}, status=200)

def get_user_message(request, uuid: str, message_id: int):
    """
    Retrieve and return a user's message by message ID.

    Returns the base64-encoded encrypted message and its type.
    """
    try:
        # Get the message by its ID
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

def craft_message(data, uuid):
    """
    Helper function to create a Message object from provided data.

    Decodes the base64-encoded AES key and encrypted message, creates and saves the AesKeyEncWithAbe,
    and returns a Message object (not saved to the database).
    """
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

    return message

def post_user_message(request, uuid):
    """
    Create a new message for the user and store it in the database.

    Expects 'b64_serial_abe_policy_enc_key', 'b64_serial_enc_message', and 'message_type' in the request body.
    """
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

        message = craft_message(data, uuid)
        # Save the instance to the database
        message.save()
        # Return success response with the created ID
        return JsonResponse({"message": "Message created", "id": message.message_id}, status=201)

    except json.JSONDecodeError:
        # Handle JSON parsing error
        return JsonResponse({"error": "Invalid JSON"}, status=400)

def put_user_message(request, uuid):
    """Update a user's message. (Function not implemented yet.)"""
    return None

def get_auth_public_key(request, auth_id):
    """
    Retrieve and return the public key of an authority.

    Returns the base64-encoded public key components.
    """
    pub_key_id = Authority.objects.get(id=auth_id).pub_key_id
    pub_key = PubKey.objects.get(id=pub_key_id)
    b64_serial_pub_key = {
        'b64_serial_public_key_egga': b64.b64encode(pub_key.egga_serial).decode('utf-8'),
        'b64_serial_public_key_gy': b64.b64encode(pub_key.gy_serial).decode('utf-8')
    }
    return JsonResponse(b64_serial_pub_key)

def get_challenge_auth_patient(request, rep_id: str, uuid: str, type: str):
    """
    Generate a challenge for an authority representative to authenticate a patient.

    Returns a base64-encoded serialized challenge encrypted under a policy based on the patient's authorities.
    """
    # Get patient representatives
    patient_rep = PatientRep.objects.filter(patient=uuid)
    auth_set = set()

    check_auth = ""
    check_attr = ""

    if type == "HEALTH":
        check_auth = "HOSPITAL"
        check_attr = "DOCTOR"
    elif type == "TRAINING":
        check_auth = "HEALTHCLUB"
        check_attr = "HEALTHCLUBTRAINER"

    for rep in patient_rep:
        rep_attributes = rep.rep.attributes
        for attribute in rep_attributes:
            authority_id = attribute.split('@')[1]
            if check_auth in authority_id:
                auth_set.add(authority_id)

    if not auth_set:
        return JsonResponse({"error": "Patient has no hospitals"}, status=400)

    ma_abe = MAABEService()
    # Generate a random challenge
    challenge = ma_abe.helper.get_random_group_element()
    challenge_map[rep_id] = (challenge, uuid, type)
    policy = "(" + " OR ".join(f"{check_attr}@{auth}" for auth in auth_set) + ")"
    encrypted_challenge = ma_abe.helper.encrypt(challenge, policy)

    # Serialize challenge
    serial_challenge = serialize_encrypted_abe_ciphertext(encrypted_challenge, ma_abe.group)
    # Encode challenge
    b64_serial_challenge = b64.b64encode(serial_challenge).decode('utf-8')

    return JsonResponse({"b64_serial_challenge": b64_serial_challenge})

def post_challenge_auth_patient(request, rep_id: str, uuid: str, type: str):
    """
    Validate the challenge response from the authority representative.

    Expects 'b64_serial_challenge' and 'b64_serial_rep_message' in the request body.
    """
    try:
        data = json.loads(request.body)
        # Validate required fields
        if 'b64_serial_challenge' not in data or 'b64_serial_rep_message' not in data:
            return JsonResponse({"error": "Missing fields"}, status=400)

        b64_serial_challenge = data['b64_serial_challenge']
        serial_challenge = b64.b64decode(b64_serial_challenge)
        ma_abe = MAABEService()
        # Deserialize challenge
        challenge = ma_abe.group.deserialize(serial_challenge)
        print(f"Challenge: {challenge}")

        if rep_id not in challenge_map:
            # Reset challenge
            challenge_map[rep_id] = None
            return JsonResponse({"error": "Challenge failed"}, status=403)

        if (
            challenge_map[rep_id][0] != challenge
            or challenge_map[rep_id][1] != uuid
            or challenge_map[rep_id][2] != type
        ):
            # Reset challenge
            challenge_map[rep_id] = None
            return JsonResponse({"&&error": "Challenge failed"}, status=403)

        b64_serial_rep_message = data['b64_serial_rep_message']

        message = craft_message(b64_serial_rep_message, uuid)

        # Reset challenge
        challenge_map[rep_id] = None

        # Save the instance to the database
        message.save()

        return JsonResponse({"message": "Challenge solved"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


def get_patients(request):
    """
    Retrieve and return all patients from the database.

    Returns a list of patient IDs.
    """
    patients = Patient.objects.all()
    patient_ids = [patient.patient_id for patient in patients]
    return JsonResponse({"patients": patient_ids})


def get_representatives(request):
    """
    Retrieve and return all representatives from the database.

    Returns a list of representative IDs and their associated attribute lists
    """
    reps = AuthorityRep.objects.all()
    rep_data = {}
    for rep in reps:
        rep_data[rep.rep_id] = rep.attributes
    return JsonResponse(rep_data)