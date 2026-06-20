-- Sample SQL Database Dump with PII
-- Company: TechCorp India Pvt Ltd
-- Generated: 2024-01-15

CREATE DATABASE IF NOT EXISTS employee_db;
USE employee_db;

CREATE TABLE employees (
    id INT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255),
    phone VARCHAR(20),
    aadhaar_number VARCHAR(14),
    pan_number VARCHAR(10),
    address TEXT,
    date_of_birth DATE,
    ip_address VARCHAR(15),
    department VARCHAR(100),
    salary DECIMAL(10,2)
);

-- Insert sample employee records with PII

INSERT INTO employees (first_name, last_name, email, phone, aadhaar_number, pan_number, address, date_of_birth, ip_address, department, salary) 
VALUES 
('Rajesh', 'Kumar', 'rajesh.kumar@techcorp.in', '+91-9876543210', '1234 5678 9012', 'ABCDE1234F', '123 MG Road, Bangalore, Karnataka 560001', '1985-03-15', '192.168.1.100', 'Engineering', 85000.00);

INSERT INTO employees (first_name, last_name, email, phone, aadhaar_number, pan_number, address, date_of_birth, ip_address, department, salary) 
VALUES 
('Priya', 'Sharma', 'priya.sharma@techcorp.in', '09876543210', '987654321098', 'FGHIJ5678K', '456 Park Street, Mumbai, Maharashtra 400001', '1990-07-22', '10.0.0.50', 'Marketing', 65000.00);

INSERT INTO employees (first_name, last_name, email, phone, aadhaar_number, pan_number, address, date_of_birth, ip_address, department, salary) 
VALUES 
('Amit', 'Patel', 'amit.patel@gmail.com', '+91 87654 32109', '4567 8901 2345', 'KLMNO9012P', '789 Nehru Place, New Delhi, Delhi 110019', '1988-11-08', '172.16.0.25', 'Sales', 72000.00);

INSERT INTO employees (first_name, last_name, email, phone, aadhaar_number, pan_number, address, date_of_birth, ip_address, department, salary) 
VALUES 
('Sneha', 'Reddy', 'sneha.reddy@yahoo.co.in', '918765432109', '7890 1234 5678', 'PQRST3456U', '321 Hitech City, Hyderabad, Telangana 500081', '1992-01-30', '192.168.0.200', 'HR', 58000.00);

INSERT INTO employees (first_name, last_name, email, phone, aadhaar_number, pan_number, address, date_of_birth, ip_address, department, salary) 
VALUES 
('Vikram', 'Singh', 'vikram.singh@outlook.com', '080-12345678', '2345 6789 0123', 'UVWXY7890Z', '654 Anna Salai, Chennai, Tamil Nadu 600002', '1983-09-12', '10.10.10.10', 'Operations', 95000.00);

-- Customer contact table with PII
CREATE TABLE customers (
    customer_id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(200),
    email VARCHAR(255),
    phone VARCHAR(20),
    alternate_phone VARCHAR(20),
    aadhaar_number VARCHAR(14),
    pan_number VARCHAR(10),
    residential_address TEXT,
    office_address TEXT,
    date_of_birth DATE,
    credit_card_number VARCHAR(19),
    ip_address VARCHAR(15)
);

INSERT INTO customers (full_name, email, phone, alternate_phone, aadhaar_number, pan_number, residential_address, office_address, date_of_birth, credit_card_number, ip_address)
VALUES 
('Ananya Gupta', 'ananya.gupta@customer.in', '+91-9988776655', '022-12345678', '3456 7890 1234', 'ABCPQ1234D', '45 Salt Lake, Kolkata, West Bengal 700091', 'Sector 5, Kolkata 700091', '1995-05-20', '4532-1234-5678-9012', '203.0.113.50');

INSERT INTO customers (full_name, email, phone, alternate_phone, aadhaar_number, pan_number, residential_address, office_address, date_of_birth, credit_card_number, ip_address)
VALUES 
('Rahul Verma', 'rahul.verma@email.com', '919988776655', '+91-11-12345678', '5678 9012 3456', 'XYZAB5678C', '12 Jubilee Hills, Hyderabad 500033', 'Madhapur, Hyderabad 500081', '1987-12-03', '4111-1111-1111-1111', '198.51.100.25');

-- Contact preferences
CREATE TABLE contact_preferences (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255),
    phone VARCHAR(20),
    preferred_contact_method VARCHAR(20),
    emergency_contact_name VARCHAR(100),
    emergency_contact_phone VARCHAR(20)
);

INSERT INTO contact_preferences (email, phone, preferred_contact_method, emergency_contact_name, emergency_contact_phone)
VALUES 
('contact@example.in', '+91-9000012345', 'email', 'Suresh Kumar', '+91-9876500001'),
('info@company.co.in', '09123456789', 'phone', 'Meera Devi', '919876500002');

-- Audit log reference (contains sensitive data)
CREATE TABLE audit_reference (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_email VARCHAR(255),
    user_ip VARCHAR(15),
    action_description TEXT,
    timestamp DATETIME
);

INSERT INTO audit_reference (user_email, user_ip, action_description, timestamp)
VALUES 
('admin@techcorp.in', '192.168.1.1', 'Accessed employee records', '2024-01-15 10:30:00'),
('manager@techcorp.in', '10.0.0.100', 'Downloaded customer report', '2024-01-15 14:45:00');
