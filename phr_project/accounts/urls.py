from django.urls import path
from . import views

urlpatterns = [

    # == API endpoints ==

    path('api/v1/public_parameters', views.abe_public_parameters, name ='Get_Public_parameters'),
    path('api/v1/patients', views.patients, name ='Get_Patient_IDs'),
    path('api/v1/representatives', views.representatives, name ='Get_Representatives_IDs'),
    path('api/v1/auth_public_key/<str:auth_id>', views.auth_public_key, name='Get_Auth_Public_Key'),
    path('api/v1/patient/<str:uuid>/keys', views.patient_secret_key, name ='Get_User_MSK'),
    path('api/v1/rep/<str:uuid>/keys', views.rep_secret_key, name ='Get_User_MSK'),
    # path('api/v1/user/<str:uuid>', views.user_message_aes_key, name ='Retrieve_user_keys'),
    path('api/v1/policy_doc_ins_emp/<str:uuid>', views.policy_doc_ins_emp, name ='Retrieve_policy_doc_ins_emp_by_uuid'),
    path('api/v1/user/<str:uuid>/message/<int:message_id>', views.user_message, name='Update_patient_PHR'),
    path('api/v1/hospital/<str:rep_id>/patient/<str:uuid>/message', views.challenge_hospital_patient, name='Hospital_patient_challenge'),
    path('api/v1/healthclub/<str:rep_id>/patient/<str:uuid>/message', views.challenge_healthclub_patient, name='Healthclub_patient_challenge')

]