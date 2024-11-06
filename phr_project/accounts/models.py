from django.db import models

from accounts.utils.constants import DEFAULT_ABE_PUBLIC_PARAMS_INDEX


# Authority with Keys

class SecKey(models.Model):
    id = models.AutoField(primary_key=True)
    alpha_serial = models.BinaryField()
    y_serial = models.BinaryField()

class PubKey(models.Model):
    id = models.AutoField(primary_key=True)
    egga_serial = models.BinaryField()
    gy_serial = models.BinaryField()

def add_authority(auth_id, serial_keys):
    # Create Authority instance
    authority = Authority(
        id=auth_id,
        name=auth_id,
        sec_key=SecKey.objects.create(
            alpha_serial=serial_keys['serial_secret_key_alpha'],
            y_serial=serial_keys['serial_secret_key_y']
        ),
        pub_key=PubKey.objects.create(
            egga_serial=serial_keys['serial_public_key_egga'],
            gy_serial=serial_keys['serial_public_key_gy']
        ),
    )
    # Save the instance to the database
    authority.save()

class Authority(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    sec_key = models.OneToOneField(SecKey, on_delete=models.CASCADE)
    pub_key = models.OneToOneField(PubKey, on_delete=models.CASCADE)
    # authority_type = models.CharField(max_length=20, choices=TEST_AUTH_TYPES)
    attributes = models.JSONField(default=list)

def add_authority_rep(name, attributes, rep_id=None, rep_type=None, authority_id=None):
    try:
        # Create a new AuthorityRep record
        authority_rep = AuthorityRep.objects.create(
            name=name,
            #rep_type=rep_type,
            attributes=attributes
        )
        authority_rep.save()

        return authority_rep

    except Exception as e:
        print(e)
        return None

class AuthorityRep(models.Model):
    rep_id = models.AutoField(primary_key=True)
    # authority = models.ForeignKey(Authority, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    # rep_type = models.CharField(max_length=25, choices=TEST_REP_TYPE_CHOICES)
    attributes = models.JSONField(default=list)

# Patient Models

def add_patient(patient_id):
    attribute: str = 'PATIENT@PHR'
    patient = Patient.objects.create(
        patient_id=patient_id,
        name=patient_id,
        attributes=[attribute]
    )
    patient.save()
    return patient

class Patient(models.Model):
    patient_id = models.CharField(max_length=255, primary_key=True)
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

def add_public_params(g1_serial, g2_serial, egg_serial):
    ma_abe_public_params = MAABEPublicParams.objects.create(
        id=DEFAULT_ABE_PUBLIC_PARAMS_INDEX,
        g1_serial=g1_serial,
        g2_serial=g2_serial,
        egg_serial=egg_serial
    )
    ma_abe_public_params.save()
    return ma_abe_public_params

class MAABEPublicParams(models.Model):
    id = models.AutoField(primary_key=True)
    g1_serial = models.BinaryField()
    g2_serial = models.BinaryField()
    egg_serial = models.BinaryField()