"""
Database Management Module
Handles SQLite schema creation, CRUD operations for meters, regions, keys, and audit logs.
Designed for Academic Demonstration - Scalable KDC RSA System
"""

import sqlite3
import hashlib
import os
import datetime
from rsa import generate_rsa_keys

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'kdc.db')


def get_db_connection():
    """Creates a connection to the SQLite database with dict-like row factory."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Hashes passwords using SHA-256 for admin security."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def init_db():
    """Initializes all database tables and inserts default admin/regions if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Regions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS regions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            region_id TEXT UNIQUE NOT NULL,
            region_name TEXT NOT NULL,
            kdc_status TEXT DEFAULT 'ACTIVE'
        )
    ''')

    # 2. Meters Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS meters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT UNIQUE NOT NULL,
            region_id TEXT NOT NULL,
            location TEXT NOT NULL,
            meter_type TEXT DEFAULT 'Smart Electricity Meter',
            status TEXT DEFAULT 'ACTIVE',
            key_version INTEGER DEFAULT 1,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (region_id) REFERENCES regions (region_id)
        )
    ''')

    # 3. Keys Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT NOT NULL,
            public_exponent TEXT NOT NULL,
            modulus TEXT NOT NULL,
            private_exponent TEXT NOT NULL,
            key_version INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expiry_date TIMESTAMP,
            status TEXT DEFAULT 'ACTIVE',
            FOREIGN KEY (meter_id) REFERENCES meters (meter_id)
        )
    ''')

    # 4. Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT,
            operation TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result TEXT NOT NULL,
            description TEXT
        )
    ''')

    # 5. Admin Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert default admin if none exists
    cursor.execute("SELECT count(*) FROM admin_users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            ("admin", hash_password("admin123"))
        )

    # Insert default regions if none exist
    cursor.execute("SELECT count(*) FROM regions")
    if cursor.fetchone()[0] == 0:
        default_regions = [
            ("R1", "North Substation KDC", "ACTIVE"),
            ("R2", "South Substation KDC", "ACTIVE"),
            ("R3", "East Industrial KDC", "ACTIVE")
        ]
        cursor.executemany(
            "INSERT INTO regions (region_id, region_name, kdc_status) VALUES (?, ?, ?)",
            default_regions
        )

    conn.commit()
    conn.close()


def log_audit(meter_id: str, operation: str, result: str, description: str):
    """Inserts a structured entry into the audit_logs table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (meter_id, operation, result, description) VALUES (?, ?, ?, ?)",
        (meter_id, operation, result, description)
    )
    conn.commit()
    conn.close()


def register_smart_meter(meter_id: str, region_id: str, location: str, meter_type: str = "Smart Electricity Meter", key_bits: int = 16):
    """
    Registers a new Smart Meter:
    1. Validates inputs and checks for duplicates.
    2. Assigns to Region KDC.
    3. Automatically generates RSA Key pair.
    4. Persists meter and key details.
    5. Writes audit logs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Input sanitization and check
    meter_id = meter_id.strip().upper()
    if not meter_id:
        return False, "Meter ID cannot be empty."

    cursor.execute("SELECT id FROM meters WHERE meter_id = ?", (meter_id,))
    if cursor.fetchone():
        log_audit(meter_id, "REGISTRATION", "FAILED", "Duplicate registration attempt.")
        conn.close()
        return False, f"Meter ID '{meter_id}' is already registered."

    cursor.execute("SELECT id FROM regions WHERE region_id = ?", (region_id,))
    if not cursor.fetchone():
        log_audit(meter_id, "REGISTRATION", "FAILED", f"Invalid Region ID '{region_id}'.")
        conn.close()
        return False, f"Region ID '{region_id}' does not exist."

    try:
        # Generate initial RSA Key Pair
        rsa_data = generate_rsa_keys(bits=key_bits)
        
        # Insert Meter
        cursor.execute(
            "INSERT INTO meters (meter_id, region_id, location, meter_type, status, key_version) VALUES (?, ?, ?, ?, 'ACTIVE', 1)",
            (meter_id, region_id, location, meter_type)
        )

        # Expiry date 365 days from now
        expiry = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')

        # Insert Key Metadata
        cursor.execute(
            """INSERT INTO keys 
               (meter_id, public_exponent, modulus, private_exponent, key_version, expiry_date, status) 
               VALUES (?, ?, ?, ?, 1, ?, 'ACTIVE')""",
            (
                meter_id,
                str(rsa_data['e']),
                str(rsa_data['n']),
                str(rsa_data['d']),
                expiry
            )
        )

        conn.commit()

        # Audit logs
        log_audit(meter_id, "REGISTRATION", "SUCCESS", f"Registered under region {region_id} at {location}.")
        log_audit(meter_id, "KEY_GENERATION", "SUCCESS", f"Generated RSA Version 1 Key Pair (e={rsa_data['e']}, n_bits={rsa_data['n'].bit_length()}).")

        conn.close()
        return True, "Meter registered successfully with RSA keys generated."

    except Exception as ex:
        conn.rollback()
        conn.close()
        log_audit(meter_id, "REGISTRATION", "ERROR", str(ex))
        return False, f"Error registering meter: {str(ex)}"


def get_meter(meter_id: str):
    """Retrieves meter details along with its active RSA key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.*, k.public_exponent, k.modulus, k.private_exponent, k.status as key_status, k.created_at as key_created_at
        FROM meters m
        LEFT JOIN keys k ON m.meter_id = k.meter_id AND k.status = 'ACTIVE'
        WHERE m.meter_id = ?
    """, (meter_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_meters():
    """Retrieves all registered meters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM meters ORDER BY registered_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_audit_logs(limit: int = 100):
    """Retrieves latest audit logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def verify_admin_login(username: str, password: str) -> bool:
    """Verifies admin credentials."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed = hash_password(password)
    cursor.execute("SELECT id FROM admin_users WHERE username = ? AND password_hash = ?", (username, hashed))
    user = cursor.fetchone()
    conn.close()
    return user is not None