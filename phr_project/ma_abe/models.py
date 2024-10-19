from django.db import models
from django.contrib.auth.models import User


class UserRole(models.Model):
    id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    user_attributes = models.JSONField(default=list)
    usk = models.JSONField(default=list)

    class Meta:
        abstract = True


class Patient(UserRole):
    health_data = models.JSONField()

    def __str__(self):
        return self.full_name


class Hospital(models.Model):
    name = models.CharField(max_length=255)
    patients = models.ManyToManyField(Patient, related_name='hospitals')

    ask = models.JSONField(default=list)  # Authority Secret Key for generating USKs
    public_key = models.JSONField(default=list)  # Public Key for encryption

    def __str__(self):
        return self.name


class Doctor(UserRole):
    patients = models.ManyToManyField(Patient, related_name='doctors')

    def __str__(self):
        return self.user.username


class Insurance(models.Model):
    patients = models.ManyToManyField(Patient, related_name='insurance_providers')


    def __str__(self):
        return self.name


class Employer(UserRole):
    employers = models.ManyToManyField(Patient, related_name='employers')

    def __str__(self):
        return self.name



class HealthClub(models.Model):
    name = models.CharField(max_length=255)
    members = models.ManyToManyField(Patient, related_name='health_clubs')

    ask = models.JSONField(default=list)  # Authority Secret Key for generating USKs
    public_key = models.JSONField(default=list)  # Public Key for encryption
    def __str__(self):
        return self.name