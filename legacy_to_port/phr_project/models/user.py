from attr import dataclass


@dataclass
class User:
    user_id : int
    name : str
    surname : str
    password : str
    email : str
    username : str

