import mariadb

from models.patient import Patient


class Database:

    @staticmethod
    def create_connection():
        """ Create a database connection to MariaDB """
        conn = mariadb.connect(
            user="phr",
            password="phr",
            host="127.0.0.1",
            port=3306,
            database="patientsDatabase"

        )
        print("Connected to the database")
        return conn

    @staticmethod
    def insert_patient(conn, patient : Patient):
        """ Insert a new user into the users table """
        try:
            cursor = conn.cursor()
            query = """INSERT INTO users (id,username, password, name, surname, email)
                               VALUES (?, ?, ?, ?, ?, ?)"""
            cursor.execute(query, (patient.user_id,
                                   patient.username,
                                   patient.password,
                                   patient.name,
                                   patient.surname,
                                   patient.email
                                   )
                           )
            conn.commit()
            print(f"User {patient.name} {patient.surname} inserted successfully.")
            query = """INSERT INTO patient (user_id, gender, medical_history, training_health_data)
                       VALUES (?, ?, ?, ?)"""
            cursor.execute(query, (patient.user_id,
                                   patient.gender,
                                   patient.medical_history,
                                   patient.training_health_data
                                   )
                            )
            conn.commit()
            return cursor.lastrowid
        except mariadb.Error as e:
            print(f"Error inserting into users table: {e}")

    @staticmethod
    def fetch_patients(conn):
        """ Fetch all patients from the patient table """
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.id, u.username, u.name, u.surname, u.email, u.password
                FROM users u
                JOIN patient p ON u.id = p.user_id
            """)
            result = cursor.fetchall()
            for row in result:
                print(row)
        except mariadb.Error as e:
            print(f"Error fetching from patient table: {e}")

    @staticmethod
    def close_connection(conn):
        """ Close the database connection """
        if conn:
            conn.close()
            print("MariaDB connection closed")


if __name__ == "__main__":
    patient = Patient(
        user_id=11,
        name="tua",
        surname="madre",
        password="password",
        email="email",
        username="username_11",
        gender="MALE",
        medical_history="No medical history",
        training_health_data="No training health data"
    )
    conn = Database.create_connection()
    Database.insert_patient(conn, patient)
    Database.fetch_patients(conn)
    Database.close_connection(conn)