import sqlite3
from sqlite3 import Error


def create_connection():
    """
    Create a database connection to the SQLite database specified by db_file.
    :return: connection object or None
    """
    connection = None
    try:
        connection = sqlite3.connect('../../client.db.sqlite3')
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
        id INTEGER PRIMARY KEY,
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
        id INTEGER PRIMARY KEY,
        g1_serial TEXT NOT NULL,
        g2_serial TEXT NOT NULL,
        egg_serial TEXT NOT NULL
    );
    """
    cursor.execute(public_params_table_query)

if __name__ == '__main__':
    initialize_db()