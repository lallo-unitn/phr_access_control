from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # path('register/', views.register, name='register'),
    # path('login/', auth_views.LoginView.as_view(), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # path('profile/', views.profile, name='profile'),
    # path('', auth_views.LoginView.as_view(), name='login'),  # For profile access

    # == API endpoints ==

    path('api/v1/user_setup/<str:user_type>', views.get_user_secret_key, name = 'Get_User_MSK'),
    path('api/v1/user/<str:uuid>', views.get_user_keys, name = 'Retrieve_user_keys'),
    path('api/v1/phr/<str:uuid>', views.get_user_record, name='Update_patient_PHR'),
]