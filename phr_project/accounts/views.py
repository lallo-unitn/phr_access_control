# accounts/views.py
from typing import List, Mapping

from accounts.api_dummy_data.dummy import __get_test_enc_messages, __get_test_user_attr
from accounts.models import AesKeyEncWithAbe, Message
#from django.shortcuts import render, redirect
#from django.contrib import messages

from ma_abe.services.ma_abe_service import MAABEService
#from .forms import UserRegisterForm
#from django.contrib.auth import views as auth_views
#from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import json


# def register(request):
#     if request.method == 'POST':
#         form = UserRegisterForm(request.POST)
#         if form.is_valid():
#             form.save()
#             username = form.cleaned_data.get('username')
#             messages.success(request, f'Account created for {username}! You can now log in.')
#             return redirect('login')
#     else:
#         form = UserRegisterForm()
#     return render(request, 'accounts/register.html', {'form': form})
#
# # Login
# class CustomLoginView(auth_views.LoginView):
#     template_name = 'accounts/login.html'
#
# # Logout
# class CustomLogoutView(auth_views.LogoutView):
#     template_name = 'accounts/logout.html'
#
# @login_required
# def profile(request):
#     return render(request, 'accounts/profile.html')

def get_user_secret_key(request, uuid: str):
    # API Endpoint 1
    # --------------
    #   The client will perform a GET request with a number from 1 - 5
    #   depending on what type of person he is (e.g. Patient, Doctor)
    #
    #   The server will return the user master secret key and the user id.
    if request.method == 'GET':
        ma_abe_service = MAABEService()

        user_attrs: List = __get_test_user_attr()
        user_auth_attrs: Mapping[str, List] = {}

        # iterate on the user attributes
        for user_attr in user_attrs:
            attr_name, attr_auth, attr_id = ma_abe_service.helper.unpack_attribute(user_attr)
            if attr_auth not in user_auth_attrs:
                user_auth_attrs[attr_auth] = []
            user_auth_attrs[attr_auth].append(user_attr)

        user_keys_by_auth: Mapping[str, List] = {}

        for auth, user_attrs in user_auth_attrs.items():
            user_keys_by_auth[auth] = ma_abe_service.helper.gen_user_key(auth, uuid, user_attrs)

        merged_user_keys = ma_abe_service.helper.merge_dicts(*user_keys_by_auth.values())

        user_abe_keys = {'GID': uuid, 'keys': merged_user_keys}

        return JsonResponse(user_abe_keys)

def get_user_keys(request, uuid: str, message_id = None):
    # PUT expecting a message_id and JSON { "c_serial": "R2VuZXJhdGVkU2VyaWFsRGF0YQ==" }
    # serialized using ma_abe.utils.serial.serialize_encrypted_aes_key

    # Same for POST but without message_id

    # API Endpoint 2
    # --------------
    #   The client will either perform a GET request in order to retrieve
    #   someone else's encrypted AES key to access their PHR, or a POST
    #   request in order to send to the server their encrypted AES keys.
    #
    #   For a GET request the server will return the encrypted AES keys
    #   of the requested user (if they exist).
    if request.method == 'GET':
        messages: dict = __get_test_enc_messages()
        enc_aes_keys: dict = {}

        for message_id, enc_message in messages.items():
            enc_aes_keys[message_id] = enc_message['abe_policy_enc_key']

        return JsonResponse(enc_aes_keys)

    elif request.method == 'POST':

        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)
            # Validate required fields
            if 'c_serial' not in data:
                return JsonResponse({"error": "Missing 'c_serial' field"}, status=400)
            # Create AesKeyEncWithAbe instance
            aes_key_enc_with_abe = AesKeyEncWithAbe(
                c_serial=data['c_serial']
            )
            # Save the instance to the database
            aes_key_enc_with_abe.save()
            # Return success response with the created ID
            return JsonResponse({"message": "AesKeyEncWithAbe created", "id": aes_key_enc_with_abe.id}, status=201)

        except json.JSONDecodeError:
            # Handle JSON parsing error
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    elif request.method == 'PUT' and message_id is not None:
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

    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)

def get_user_record(request, uuid: str):
    # API Endpoint 3
    # --------------
    #   The client will either perform a GET request in order to retrieve
    #   someone else's encrypted PHR or a POST request to update their own
    #   PHR.
    #
    #   For a GET request the server will return the encrypted AES keys
    #   of the requested user (if they exist).
    if request.method == 'GET':
        messages: dict = __get_test_enc_messages()
        enc_record: dict = {}

        for message_id, enc_message in messages.items():
            enc_record[message_id] = enc_message['sym_enc_file']

        return JsonResponse(enc_record)

