from django.db import models
from django.contrib.auth.models import User

class Patient(models.Model):
    UserID = models.ForeignKey(User, on_delete=models.CASCADE)
    Gender = models.CharField(max_length = 1)
    HealthHistory = models.CharField(max_length = 255)
    TrainingHealthData = models.CharField(max_length = 255)

    @staticmethod
    def GetPrivileges() -> list[str]:
        return ["PATIENT@PHR"]