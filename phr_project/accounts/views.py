# accounts/views.py

from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse

from accounts.services import user_service

# API Endpoint 1
# --------------
#   The client will perform a GET request with a number from 1 to 5
#   depending on what type of person he is (e.g. Patient, Doctor)
#
#   The server will return the user master secret key and the user id.
@csrf_exempt
def user_secret_key(request, uuid: str) :
    if request.method == 'GET':
        return user_service.get_user_secret_key(request, uuid)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)
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
def user_message_aes_key(request, uuid: str, message_id = None):

    if request.method == 'GET':
        return user_service.get_message_aes_key(request, uuid, message_id)

    elif request.method == 'POST':
        return user_service.post_message_aes_key(request, uuid, message_id)

    elif request.method == 'PUT' and message_id is not None:
        return user_service.put_message_aes_key(request, uuid, message_id)

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
@csrf_exempt
def get_user_message(request, uuid: str):
    if request.method == 'GET':
        return user_service.get_user_message(request, uuid)
    elif request.method == 'POST':
        return user_service.post_user_message(request, uuid)
    elif request.method == 'PUT':
        return user_service.put_user_message(request, uuid)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)


