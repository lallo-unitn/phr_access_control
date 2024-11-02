PAIRING_GROUP: str ="SS512"
DEFAULT_ABE_PUBLIC_PARAMS_INDEX: int = 0
TEST_AUTH_TYPES = [
        'PHR',
        'HOSPITAL',
        'INSURANCE',
        'EMPLOYER',
        'HEALTHCLUB',
    ]

TEST_AUTH_ATTRS: dict = {
        'PHR': ['PATIENT@PHR'],
        'HOSPITAL1': ['DOCTOR@HOSPITAL1'],
        'HOSPITAL2': ['DOCTOR@HOSPITAL2'],
        'INSURANCE1': ['INSURANCEREP@INSURANCE1'],
        'INSURANCE2': ['INSURANCEREP@INSURANCE2'],
        'EMPLOYER1': ['EMPLOYERREP@EMPLOYER1'],
        'EMPLOYER2': ['EMPLOYERREP@EMPLOYER2'],
        'HEALTHCLUB1': ['HEALTHCLUBTRAINER@HEALTHCLUB1'],
        'HEALTHCLUB2': ['HEALTHCLUBTRAINER@HEALTHCLUB2']
    }

TEST_REP_TYPE_CHOICES = [
        'DOCTOR',
        'INSURANCEREP',
        'EMPLOYERREP',
        'HEALTHCLUBTRAINER'
    ]

SERVER_URL = 'http://localhost:8000'
API_VERSION = 'api/v1'