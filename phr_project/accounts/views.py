# accounts/views.py

from django.views.decorators.csrf import csrf_exempt

from accounts.services.user_service import post_user_keys, put_user_keys

from django.http import JsonResponse

# API Endpoint 1
# --------------
#   The client will perform a GET request with a number from 1 to 5
#   depending on what type of person he is (e.g. Patient, Doctor)
#
#   The server will return the user master secret key and the user id.
def get_user_secret_key(request, uuid: str):
    return get_user_secret_key(request, uuid)


# API Endpoint 2
# --------------
# PUT expecting a message_id and JSON { "c_serial": "R2VuZXJhdGVkU2VyaWFsRGF0YQ==" }
# serialized using ma_abe.utils.serial.serialize_encrypted_aes_key and then base64 encoded
# Same for POST but without message_id
# --------------
#   The client will either perform a GET request in order to retrieve
#   someone else's encrypted AES key to access their PHR, or a POST
#   request in order to send to the server their encrypted AES keys.
#   For a GET request the server will return the encrypted AES keys
#   of the requested user (if they exist).
@csrf_exempt
def get_user_keys(request, uuid: str, message_id = None):

    if request.method == 'GET':
        return get_user_keys(request, uuid, message_id)

    elif request.method == 'POST':
        return post_user_keys(request, uuid, message_id)

    elif request.method == 'PUT' and message_id is not None:
        return put_user_keys(request, uuid, message_id)

    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)


# API Endpoint 3
# --------------
#   The client will either perform a GET request in order to retrieve
#   someone else's encrypted PHR or a POST request to update their own
#   PHR.
#
#   For a GET request the server will return the encrypted AES keys
#   of the requested user (if they exist).
def get_user_record(request, uuid: str):
    return get_user_record(request, uuid)

