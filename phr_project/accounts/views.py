# accounts/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegisterForm
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! You can now log in.')
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'accounts/register.html', {'form': form})

# Login
class CustomLoginView(auth_views.LoginView):
    template_name = 'accounts/login.html'

# Logout
class CustomLogoutView(auth_views.LogoutView):
    template_name = 'accounts/logout.html'

@login_required
def profile(request):
    return render(request, 'accounts/profile.html')

def get_user_secret_key(request, user_type: str):
    # API Endpoint 1
    # --------------
    #   The client will perform a GET request with a number from 1 - 5
    #   depending on what type of person he is (e.g. Patient, Doctor)
    #
    #   The server will return the user master secret key and the user id.
    return JsonResponse({'foo':'bar'})

def get_user_keys(request, uuid: str):
    # API Endpoint 2
    # --------------
    #   The client will either perform a GET request in order to retrieve
    #   someone else's encrypted AES key to access their PHR, or a POST
    #   request in order to send to the server their encrypted AES keys.
    #
    #   For a GET request the server will return the encrypted AES keys
    #   of the requested user (if they exist).
    return JsonResponse({'foo': uuid})

def get_user_record(request, uuid: str):
    # API Endpoint 3
    # --------------
    #   The client will either perform a GET request in order to retrieve
    #   someone else's encrypted PHR or a POST request to update their own
    #   PHR.
    #
    #   For a GET request the server will return the encrypted AES keys
    #   of the requested user (if they exist).
    return JsonResponse({'foo':'bar'})
