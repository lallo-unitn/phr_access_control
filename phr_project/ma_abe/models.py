from django.db import models

# Authority with Keys

class SecKey(models.Model):
    alpha_serial = models.BinaryField()
    y_serial = models.BinaryField()

class PubKey(models.Model):
    egga_serial = models.BinaryField()
    gy_serial = models.BinaryField()

class Authority(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    sec_key = models.OneToOneField(SecKey, on_delete=models.CASCADE)
    pub_key = models.OneToOneField(PubKey, on_delete=models.CASCADE)
    AUTHORITY_TYPE_CHOICES = [
        ('HOSPITAL', 'Hospital'),
        ('HEALTH_CLUB', 'Health Club'),
        ('INSURANCE_COMPANY', 'Insurance Company'),
        ('WORK_COMPANY', 'Work Company'),
    ]
    authority_type = models.CharField(max_length=20, choices=AUTHORITY_TYPE_CHOICES)
    attributes = models.JSONField(default=list)

class AuthorityRep(models.Model):
    rep_id = models.AutoField(primary_key=True)
    authority = models.ForeignKey(Authority, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    REP_TYPE_CHOICES = [
        ('DOCTOR', 'Doctor'),
        ('INSURANCE_REP', 'Insurance Representative'),
        ('WORK_REP', 'Employer'),
        ('HEALTH_CLUB_REP', 'Health Club Representative'),
    ]
    rep_type = models.CharField(max_length=25, choices=REP_TYPE_CHOICES)
    attributes = models.JSONField(default=list)


# Patient Models

class Patient(models.Model):
    patient_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    attributes = models.JSONField(default=list)


class PatientRep(models.Model):
    rep = models.ForeignKey(AuthorityRep, on_delete=models.CASCADE)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)

# Message and Encryption Models

class AesKeyEncWithAbe(models.Model):
    id = models.AutoField(primary_key=True)
    c_serial = models.BinaryField()

class Message(models.Model):
    message_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    aes_enc_message = models.BinaryField()
    aes_key_enc_with_abe = models.ForeignKey(AesKeyEncWithAbe, on_delete=models.CASCADE)
    MESSAGE_TYPE_CHOICES = [
        ('HEALTH', 'Health'),
        ('TRAINING', 'Training'),
    ]
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPE_CHOICES)

