from dataclasses import dataclass

from models.user import User

@dataclass
class Patient(User):
    gender : str
    medical_history : str
    training_health_data : str
    usr_attrs = ['PATIENT@PHR']

    #initialize the patient
    def __init__(self, user_id, name, surname, password, email, username, gender, medical_history, training_health_data):
        super().__init__(user_id, name, surname, password, email, username)
        self.gender = gender
        self.medical_history = medical_history
        self.training_health_data = training_health_data






