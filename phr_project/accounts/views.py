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


def get_user_keys(request, uuid: str):  # API Endpoint 1
    # Sends keys to the client
    return JsonResponse({'foo': uuid})

def handle_aes_keys(request, uuid: str): # API Endpoint 2
    if request.method == 'GET':
            # GET Request
    if request.method == 'POST':
            # POST Request

def handle_phr(request, uuid: str):
    return JsonResponse({'foo':'bar'})

# Init: separate script
# 