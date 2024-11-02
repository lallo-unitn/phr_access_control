import json
import sqlite3
from pathlib import Path
from sqlite3 import Error

from services.constants import DEFAULT_ABE_PUBLIC_PARAMS_INDEX


def db_create_connection():
    """
    Create a database connection to the SQLite database specified by db_file.
    :return: connection object or None
    """
    connection = None
    try:
        script_dir = Path(__file__).parent.absolute()
        database_file = script_dir / "client.db.sqlite3"
        connection = sqlite3.connect(database_file)
        print("Successfully connected to the database")
    except Error as e:
        print(f"Error: '{e}' occurred while connecting to the database")

    return connection

def db_create_auth_pub_keys_table(cursor):
    # Replace with your initialization SQL commands
    auth_pub_keys_table_query = """
    CREATE TABLE IF NOT EXISTS auth_pub_keys(
        id TEXT PRIMARY KEY,
        serial_pub_key TEXT NOT NULL
    );
    """
    cursor.execute(auth_pub_keys_table_query)

def db_create_users_table(cursor):
    # Replace with your initialization SQL commands
    user_table_query = """
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        serial_keys TEXT NOT NULL
    );
    """
    cursor.execute(user_table_query)

def db_create_public_parameters_table(cursor):
    # Replace with your initialization SQL commands
    public_params_table_query = """
    CREATE TABLE IF NOT EXISTS public_parameters(
        id TEXT PRIMARY KEY,
        serial_g1 TEXT NOT NULL,
        serial_g2 TEXT NOT NULL,
        serial_egg TEXT NOT NULL
    );
    """
    cursor.execute(public_params_table_query)

def db_save_user(id, user_keys, username = None, password = None):
    connection = db_create_connection()
    cursor = connection.cursor()
    user_keys = json.dumps(user_keys)
    cursor.execute(
        "INSERT INTO users (id, username, password, serial_keys) VALUES (?, ?, ?, ?)",
        (id, username, password, user_keys)
    )
    connection.commit()
    connection.close()


def db_get_user(id):
    connection = db_create_connection()
    connection.row_factory = sqlite3.Row  # Enables dictionary-like access
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (id,))
    user = cursor.fetchone()
    connection.close()
    if user:
        user = dict(user)
        user["serial_keys"] = json.loads(user["serial_keys"])
    return user

def db_save_public_parameters(public_parameters):
    connection = db_create_connection()
    cursor = connection.cursor()
    # remove public parameters if they already exist
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

def db_get_public_parameters():
    connection = db_create_connection()
    connection.row_factory = sqlite3.Row  # Enables dictionary-like access
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM public_parameters WHERE id=?", (DEFAULT_ABE_PUBLIC_PARAMS_INDEX,))
    public_parameters = cursor.fetchone()
    connection.close()
    return public_parameters

def db_save_auth_pub_key(auth_id, serial_auth_pub_key):
    connection = db_create_connection()
    cursor = connection.cursor()
    serial_pub_key = json.dumps(serial_auth_pub_key)
    cursor.execute(
        "INSERT INTO auth_pub_keys (id, serial_pub_key) VALUES (?, ?)",
        (auth_id, serial_pub_key)
    )
    connection.commit()
    connection.close()

def db_get_auth_pub_key(auth_id):
    connection = db_create_connection()
    connection.row_factory = sqlite3.Row  # Enables dictionary-like access
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM auth_pub_keys WHERE id=?", (auth_id,))
    serial_auth_pub_key = cursor.fetchone()
    ret_value = None
    if serial_auth_pub_key is not None:
        ret_value = json.loads(serial_auth_pub_key['serial_pub_key'])
    connection.close()
    return ret_value

def db_initialize():
    """
    Initialize the database with the required tables.
    :return: None
    """
    connection = db_create_connection()
    if connection is None:
        print("Failed to create database connection. Exiting initialization.")
        return
    cursor = connection.cursor()
    try:
        db_create_public_parameters_table(cursor)
        db_create_users_table(cursor)
        db_create_auth_pub_keys_table(cursor)
        print("Database initialized successfully.")
    except Error as e:
        print(f"Error: '{e}' occurred while initializing the database")
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    db_initialize()