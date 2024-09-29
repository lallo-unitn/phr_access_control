import mariadb


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


def insert_user(conn, username, password, name, surname):
    """ Insert a new user into the users table """
    try:
        cursor = conn.cursor()
        query = """INSERT INTO users (username, password, name, surname)
                   VALUES (?, ?, ?, ?)"""
        cursor.execute(query, (username, password, name, surname))
        conn.commit()
        print(f"User {name} {surname} inserted successfully.")
        return cursor.lastrowid
    except mariadb.Error as e:
        print(f"Error inserting into users table: {e}")


def insert_patient(conn, user_id, gender, medical_history, training_health_data):
    """ Insert a patient record into the patient table """
    try:
        cursor = conn.cursor()
        query = """INSERT INTO patient (user_id, gender, medical_history, training_health_data)
                   VALUES (?, ?, ?, ?)"""
        cursor.execute(query, (user_id, gender, medical_history, training_health_data))
        conn.commit()
        print(f"Patient record for user_id {user_id} inserted successfully.")
    except mariadb.Error as e:
        print(f"Error inserting into patient table: {e}")


def insert_doctor(conn, user_id, specialty, license_number):
    """ Insert a doctor record into the doctor table """
    try:
        cursor = conn.cursor()
        query = """INSERT INTO doctor (user_id, specialty, license_number)
                   VALUES (?, ?, ?)"""
        cursor.execute(query, (user_id, specialty, license_number))
        conn.commit()
        print(f"Doctor record for user_id {user_id} inserted successfully.")
    except mariadb.Error as e:
        print(f"Error inserting into doctor table: {e}")


def fetch_users(conn):
    """ Fetch all users from the users table """
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        result = cursor.fetchall()
        for row in result:
            print(row)
    except mariadb.Error as e:
        print(f"Error fetching from users table: {e}")


def fetch_patients(conn):
    """ Fetch all patients from the patient table """
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, p.gender, p.medical_history, p.training_health_data
            FROM users u
            JOIN patient p ON u.id = p.user_id
        """)
        result = cursor.fetchall()
        for row in result:
            print(row)
    except mariadb.Error as e:
        print(f"Error fetching from patient table: {e}")


def fetch_doctors(conn):
    """ Fetch all doctors from the doctor table """
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, d.specialty, d.license_number
            FROM users u
            JOIN doctor d ON u.id = d.user_id
        """)
        result = cursor.fetchall()
        for row in result:
            print(row)
    except mariadb.Error as e:
        print(f"Error fetching from doctor table: {e}")


def close_connection(conn):
    """ Close the database connection """
    if conn:
        conn.close()
        print("MariaDB connection closed")


if __name__ == "__main__":
    conn = create_connection()

    if conn:
        # Insert a user and get their ID
        user_id_1 = insert_user(conn, 'new_patient', 'hashed_password', 'Jane', 'Doe')
        if user_id_1:
            insert_patient(conn, user_id_1, 'Female', 'No known issues', 'Regular gym workouts')

        # Insert a doctor
        user_id_2 = insert_user(conn, 'new_doctor', 'hashed_password', 'Dr. John', 'Smith')
        if user_id_2:
            insert_doctor(conn, user_id_2, 'General Medicine', 'LIC654321')

        # Fetch and display users, patients, and doctors
        print("\nAll Users:")
        fetch_users(conn)

        print("\nAll Patients:")
        fetch_patients(conn)

        print("\nAll Doctors:")
        fetch_doctors(conn)

        # Close the connection
        close_connection(conn)