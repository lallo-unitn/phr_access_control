# accounts/views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from accounts.services import user_service


@csrf_exempt
def abe_public_parameters(request):
    """
    Handle GET requests to obtain ABE public parameters.
    """
    if request.method == 'GET':
        return user_service.get_abe_public_parameters(request)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def user_secret_key(request, uuid: str):
    """
    Handle GET requests to obtain a user's secret key.

    Args:
        request: The HTTP request object.
        uuid (str): The user's UUID.

    Returns:
        JsonResponse: The user's secret key or an error message.
    """
    if request.method == 'GET':
        return user_service.get_user_secret_key(request, uuid)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def user_message_aes_key(request, uuid: str, message_id=None):
    """
    Handle GET, POST, and PUT requests for a user's message AES key.

    Args:
        request: The HTTP request object.
        uuid (str): The user's UUID.
        message_id (int, optional): The message ID.

    Returns:
        JsonResponse: The requested data or an error message.
    """
    if request.method == 'GET':
        return user_service.get_message_aes_key(request, uuid, message_id)
    if request.method == 'POST':
        return user_service.post_message_aes_key(request, uuid, message_id)
    if request.method == 'PUT' and message_id is not None:
        return user_service.put_message_aes_key(request, uuid, message_id)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def policy_doc_ins_emp(request, uuid: str):
    """
    Handle GET requests to obtain a user's policy document.

    Args:
        request: The HTTP request object.
        uuid (str): The user's UUID.

    Returns:
        JsonResponse: The policy document or an error message.
    """
    if request.method == 'GET':
        return user_service.get_policy_doc_ins_emp(request, uuid)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def user_message(request, uuid: str, message_id: int = None):
    """
    Handle GET, POST, and PUT requests for a user's messages.

    Args:
        request: The HTTP request object.
        uuid (str): The user's UUID.
        message_id (int, optional): The message ID.

    Returns:
        JsonResponse: The requested data or an error message.
    """
    if request.method == 'GET':
        return user_service.get_user_message(request, uuid, message_id)
    if request.method == 'POST':
        return user_service.post_user_message(request, uuid)
    if request.method == 'PUT':
        return user_service.put_user_message(request, uuid)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def challenge_rep_patient(
    request, rep_id: str, uuid: str, message_type: str, message_id: int = None
):
    """
    Handle GET and POST requests for challenges between a representative and a patient.

    Args:
        request: The HTTP request object.
        rep_id (str): The representative's ID.
        uuid (str): The patient's UUID.
        message_type (str): The type of message ("HEALTH" or "TRAINING").
        message_id (int, optional): The message ID.

    Returns:
        JsonResponse: The requested data or an error message.
    """
    if request.method == 'GET':
        return user_service.get_challenge_auth_patient(request, rep_id, uuid, message_type)
    if request.method == 'POST':
        return user_service.post_challenge_auth_patient(request, rep_id, uuid, message_type)
    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
def challenge_hospital_patient(request, rep_id: str, uuid: str):
    """
    Handle requests for challenges between a hospital representative and a patient.

    Args:
        request: The HTTP request object.
        rep_id (str): The representative's ID.
        uuid (str): The patient's UUID.

    Returns:
        JsonResponse: The requested data or an error message.
    """
    return challenge_rep_patient(request, rep_id, uuid, "HEALTH")


@csrf_exempt
def challenge_healthclub_patient(request, rep_id: str, uuid: str):
    """
    Handle requests for challenges between a health club representative and a patient.

    Args:
        request: The HTTP request object.
        rep_id (str): The representative's ID.
        uuid (str): The patient's UUID.

    Returns:
        JsonResponse: The requested data or an error message.
    """
    return challenge_rep_patient(request, rep_id, uuid, "TRAINING")


@csrf_exempt
def auth_public_key(request, auth_id: str):
    """
    Handle GET requests to obtain an authority's public key.

    Args:
        request: The HTTP request object.
        auth_id (str): The authority's ID.

    Returns:
        JsonResponse: The authority's public key or an error message.
    """
    if request.method == 'GET':
        return user_service.get_auth_public_key(request, auth_id)
    return JsonResponse({"error": "Method not allowed"}, status=405)
