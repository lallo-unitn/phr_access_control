import sqlite3
from pathlib import Path
from sqlite3 import Error

from services.constants import DEFAULT_ABE_PUBLIC_PARAMS_INDEX


def create_connection():
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


def initialize_db():
    """
    Initialize the database with the required tables.
    :return: None
    """
    connection = create_connection()
    if connection is None:
        print("Failed to create database connection. Exiting initialization.")
        return
    cursor = connection.cursor()
    try:
        create_public_parameters_table(cursor)
        create_user_table(cursor)
        print("Database initialized successfully.")
    except Error as e:
        print(f"Error: '{e}' occurred while initializing the database")
    finally:
        cursor.close()
        connection.close()

def create_user_table(cursor):
    # Replace with your initialization SQL commands
    user_table_query = """
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        k TEXT NOT NULL,
        kp TEXT NOT NULL
    );
    """
    cursor.execute(user_table_query)

def create_public_parameters_table(cursor):
    # Replace with your initialization SQL commands
    public_params_table_query = """
    CREATE TABLE IF NOT EXISTS public_parameters(
        id TEXT PRIMARY KEY,
        g1_serial TEXT NOT NULL,
        g2_serial TEXT NOT NULL,
        egg_serial TEXT NOT NULL
    );
    """
    cursor.execute(public_params_table_query)

def save_user(id, user_keys, username = None, password = None):
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (id, username, password, k, kp) VALUES (?, ?, ?, ?, ?)",
        (id, username, password, user_keys['K'], user_keys['KP'])
    )
    connection.commit()
    connection.close()

def save_public_parameters(public_parameters):
    connection = create_connection()
    cursor = connection.cursor()
    # remove public parameters if they already exist
    cursor.execute(
        "DELETE FROM public_parameters WHERE id=?",
        (DEFAULT_ABE_PUBLIC_PARAMS_INDEX,)
    )
    cursor.execute(
        "INSERT INTO public_parameters (id, g1_serial, g2_serial, egg_serial) VALUES (?, ?, ?, ?)",
        (
            DEFAULT_ABE_PUBLIC_PARAMS_INDEX,
            public_parameters['serial_g1'],
            public_parameters['serial_g2'],
            public_parameters['serial_egg']
        )
    )
    connection.commit()
    connection.close()

def get_public_parameters(id):
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM public_parameters WHERE id=?", (id,))
    public_parameters = cursor.fetchone()
    connection.close()
    return public_parameters

def get_user(id):
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (id,))
    user = cursor.fetchone()
    connection.close()
    return user

def get_public_parameters(id):
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM public_parameters WHERE id=?", (id,))
    public_parameters = cursor.fetchone()
    connection.close()
    return public_parameters

if __name__ == '__main__':
    initialize_db()