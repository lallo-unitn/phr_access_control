from django.db import models

class UserProfile(models.Model):
    gid = models.CharField(max_length=50, unique=True)  # Global ID, e.g., 'bob' or 'alice'
    attributes = models.JSONField()  # Stores attributes for multiple domains dynamically

    def __str__(self):
        return self.gid