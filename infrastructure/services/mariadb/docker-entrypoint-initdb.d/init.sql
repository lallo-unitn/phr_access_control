CREATE USER 'phr'@'%' IDENTIFIED BY 'phr';
GRANT ALL PRIVILEGES ON patientsDatabase.* TO 'phr'@'%';
FLUSH PRIVILEGES;

-- Create the database (if it doesn't exist already)
CREATE DATABASE IF NOT EXISTS patientsDatabase;
ALTER DATABASE patientsDatabase CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Switch to the newly created database
USE patientsDatabase;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password CHAR(72) NOT NULL,
    name VARCHAR(255) NOT NULL,
    surname VARCHAR(255) NOT NULL
);

-- Create patient table
CREATE TABLE IF NOT EXISTS patient (
    user_id INT UNSIGNED PRIMARY KEY,
    gender VARCHAR(255),
    medical_history TEXT,
    training_health_data TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    role VARCHAR(255) DEFAULT 'patient' NOT NULL
);

-- Create doctor table
CREATE TABLE IF NOT EXISTS doctor (
    user_id INT UNSIGNED PRIMARY KEY,
    specialty VARCHAR(255),
    license_number VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id),
    role VARCHAR(255) DEFAULT 'doctor' NOT NULL
);

-- Insert a patient into users table
INSERT INTO users (username, password, name, surname)
VALUES ('patient_user1', 'hashed_password1', 'Alice', 'Smith');

-- Retrieve user ID for the patient
SET @patient_user_id = LAST_INSERT_ID();

-- Insert patient data into patient table
INSERT INTO patient (user_id, gender, medical_history, training_health_data)
VALUES (@patient_user_id, 'Female', 'No known allergies', 'Regular exercise');

-- Insert a doctor into users table
INSERT INTO users (username, password, name, surname)
VALUES ('doctor_user1', 'hashed_password2', 'Bob', 'Jones');

-- Retrieve user ID for the doctor
SET @doctor_user_id = LAST_INSERT_ID();

-- Insert doctor data into doctor table
INSERT INTO doctor (user_id, specialty, license_number)
VALUES (@doctor_user_id, 'Cardiology', 'LIC123456');

-- Insert another patient into users table
INSERT INTO users (username, password, name, surname)
VALUES ('patient_user2', 'hashed_password3', 'John', 'Doe');

-- Retrieve user ID for the second patient
SET @patient_user_id = LAST_INSERT_ID();

-- Insert patient data into patient table
INSERT INTO patient (user_id, gender, medical_history, training_health_data)
VALUES (@patient_user_id, 'Male', 'Diabetic', 'Yoga and walking');

-- Insert another doctor into users table
INSERT INTO users (username, password, name, surname)
VALUES ('doctor_user2', 'hashed_password4', 'Dr. Emily', 'Clark');

-- Retrieve user ID for the second doctor
SET @doctor_user_id = LAST_INSERT_ID();

-- Insert doctor data into doctor table
INSERT INTO doctor (user_id, specialty, license_number)
VALUES (@doctor_user_id, 'Neurology', 'LIC789012');