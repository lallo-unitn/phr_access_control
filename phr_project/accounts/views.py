# accounts/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegisterForm
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required

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
