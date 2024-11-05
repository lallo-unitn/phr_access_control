import json
import sqlite3
from pathlib import Path
from sqlite3 import Error
from services.constants import DEFAULT_ABE_PUBLIC_PARAMS_INDEX

def db_create_connection() -> sqlite3.Connection:
    """
    Create a connection to the SQLite database.

    Returns:
        sqlite3.Connection: The connection object or None if an error occurs.
    """
    try:
        script_dir = Path(__file__).parent.absolute()
        database_file = script_dir / "client.db.sqlite3"
        connection = sqlite3.connect(database_file)
        return connection
    except Error as e:
        print(f"Error: '{e}' occurred while connecting to the database")
        return None

def db_create_auth_pub_keys_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the 'auth_pub_keys' table if it does not exist.

    Args:
        cursor (sqlite3.Cursor): The database cursor.
    """
    query = """
    CREATE TABLE IF NOT EXISTS auth_pub_keys(
        id TEXT PRIMARY KEY,
        serial_pub_key TEXT NOT NULL
    );
    """
    cursor.execute(query)

def db_create_patients_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the 'users' table if it does not exist.

    Args:
        cursor (sqlite3.Cursor): The database cursor.
    """
    query = """
    CREATE TABLE IF NOT EXISTS patients(
        id TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        keys TEXT NOT NULL
    );
    """
    cursor.execute(query)

def db_create_reps_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the 'reps' table if it does not exist.

    Args:
        cursor (sqlite3.Cursor): The database cursor.
    """
    query = """
    CREATE TABLE IF NOT EXISTS reps(
        id TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        keys TEXT NOT NULL
    );
    """
    cursor.execute(query)

def db_create_public_parameters_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the 'public_parameters' table if it does not exist.

    Args:
        cursor (sqlite3.Cursor): The database cursor.
    """
    query = """
    CREATE TABLE IF NOT EXISTS public_parameters(
        id TEXT PRIMARY KEY,
        serial_g1 TEXT NOT NULL,
        serial_g2 TEXT NOT NULL,
        serial_egg TEXT NOT NULL
    );
    """
    cursor.execute(query)

def db_save_patient(user_id: str, keys: dict, username: str = None, password: str = None) -> None:
    """
    Save a user to the database.

    Args:
        user_id (str): The user's ID.
        keys (dict): The user's keys.
        username (str, optional): The user's username.
        password (str, optional): The user's password.
    """
    connection = db_create_connection()
    if connection:
        cursor = connection.cursor()
        keys_json = json.dumps(keys)
        cursor.execute(
            "INSERT INTO patients (id, username, password, keys) VALUES (?, ?, ?, ?)",
            (user_id, username, password, keys_json)
        )
        connection.commit()
        connection.close()

def db_get_patient(user_id: str) -> dict:
    """
    Retrieve a user from the database.

    Args:
        user_id (str): The user's ID.

    Returns:
        dict: The user's data, including keys, or None if the user does not exist.
    """
    connection = db_create_connection()
    if connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM patients WHERE id=?", (user_id,))
        user = cursor.fetchone()
        connection.close()
        if user:
            user = dict(user)
            user["keys"] = json.loads(user["keys"])
            return user
    return None

def db_save_rep(user_id: str, keys: dict, username: str = None, password: str = None) -> None:
    """
    Save a representative to the database.

    Args:
        user_id (str): The representative's ID.
        keys (dict): The representative's keys.
        username (str, optional): The representative's username.
        password (str, optional): The representative's password.
    """
    connection = db_create_connection()
    if connection:
        cursor = connection.cursor()
        keys_json = json.dumps(keys)
        cursor.execute(
            "INSERT INTO reps (id, username, password, keys) VALUES (?, ?, ?, ?)",
            (user_id, username, password, keys_json)
        )
        connection.commit()
        connection.close()

def db_get_rep(user_id: str) -> dict:
    """
    Retrieve a representative from the database.

    Args:
        user_id (str): The representative's ID.

    Returns:
        dict: The representative's data, including keys, or None if the representative does not exist.
    """
    connection = db_create_connection()
    if connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM reps WHERE id=?", (user_id,))
        user = cursor.fetchone()
        connection.close()
        if user:
            user = dict(user)
            user["keys"] = json.loads(user["keys"])
            return user
    return None

def db_save_public_parameters(public_parameters: dict) -> None:
    """
    Save public parameters to the database.

    Args:
        public_parameters (dict): The public parameters to save.
    """
    connection = db_create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM public_parameters WHERE id=?",
            (DEFAULT_ABE_PUBLIC_PARAMS_INDEX,)
        )
        cursor.execute(
            "INSERT INTO public_parameters (id, serial_g1, serial_g2, serial_egg) VALUES (?, ?, ?, ?)",
            (
                DEFAULT_ABE_PUBLIC_PARAMS_INDEX,
                public_parameters['serial_g1'],
                public_parameters['serial_g2'],
                public_parameters['serial_egg']
            )
        )
        connection.commit()
        connection.close()

def db_get_public_parameters() -> dict:
    """
    Retrieve public parameters from the database.

    Returns:
        dict: The public parameters or None if they do not exist.
    """
    connection = db_create_connection()
    if connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM public_parameters WHERE id=?", (DEFAULT_ABE_PUBLIC_PARAMS_INDEX,))
        public_parameters = cursor.fetchone()
        connection.close()
        return dict(public_parameters) if public_parameters else None

def db_save_auth_pub_key(auth_id: str, serial_auth_pub_key: dict) -> None:
    """
    Save an authority's public key to the database.

    Args:
        auth_id (str): The authority's ID.
        serial_auth_pub_key (dict): The serialized public key.
    """
    connection = db_create_connection()
    if connection:
        cursor = connection.cursor()
        serial_pub_key = json.dumps(serial_auth_pub_key)
        cursor.execute(
            "INSERT INTO auth_pub_keys (id, serial_pub_key) VALUES (?, ?)",
            (auth_id, serial_pub_key)
        )
        connection.commit()
        connection.close()

def db_get_auth_pub_key(auth_id: str) -> dict:
    """
    Retrieve an authority's public key from the database.

    Args:
        auth_id (str): The authority's ID.

    Returns:
        dict: The serialized public key or None if it does not exist.
    """
    connection = db_create_connection()
    if connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM auth_pub_keys WHERE id=?", (auth_id,))
        serial_auth_pub_key = cursor.fetchone()
        connection.close()
        if serial_auth_pub_key:
            return json.loads(serial_auth_pub_key['serial_pub_key'])
    return None

def db_initialize() -> None:
    """
    Initialize the database with the required tables.
    """
    connection = db_create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            db_create_public_parameters_table(cursor)
            db_create_patients_table(cursor)
            db_create_reps_table(cursor)
            db_create_auth_pub_keys_table(cursor)
            print("Database initialized successfully.")
        except Error as e:
            print(f"Error: '{e}' occurred while initializing the database")
        finally:
            cursor.close()
            connection.close()
    else:
        print("Failed to create database connection. Exiting initialization.")

if __name__ == '__main__':
    db_initialize()
