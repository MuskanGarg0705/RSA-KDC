"""
Hierarchical Key Distribution Center (KDC) Core Module
Implements Central and Regional KDC abstractions, key rotation, key revocation,
and hierarchy navigation routines.
Designed for Academic Demonstration - Scalable KDC RSA System
"""

import datetime
from database import get_db_connection, log_audit, get_meter
from rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt


class HierarchicalKDC:
    """Core controller for Central and Regional KDC operations."""

    @staticmethod
    def get_hierarchy_tree():
        """
        Constructs and returns the full hierarchical topology:
        Central KDC -> Regional KDCs -> Smart Meters
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM regions WHERE kdc_status = 'ACTIVE'")
        regions = [dict(r) for r in cursor.fetchall()]

        tree = {
            "name": "Central KDC",
            "type": "CENTRAL",
            "status": "ONLINE",
            "children": []
        }

        for reg in regions:
            cursor.execute(
                "SELECT meter_id, location, status, key_version FROM meters WHERE region_id = ?",
                (reg['region_id'],)
            )
            meters = [dict(m) for m in cursor.fetchall()]

            reg_node = {
                "region_id": reg['region_id'],
                "name": reg['region_name'],
                "status": reg['kdc_status'],
                "meter_count": len(meters),
                "meters": meters
            }
            tree["children"].append(reg_node)

        conn.close()
        return tree

    @staticmethod
    def rotate_meter_key(meter_id: str, key_bits: int = 16):
        """
        Executes Key Rotation for a specific smart meter:
        1. Verifies meter status (must be ACTIVE).
        2. Retrieves current active key version V.
        3. Generates a new RSA key pair for V + 1.
        4. Marks previous key version as 'ROTATED'.
        5. Inserts new key as 'ACTIVE' and increments meter key_version.
        6. Logs audit trail.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM meters WHERE meter_id = ?", (meter_id,))
        meter = cursor.fetchone()

        if not meter:
            conn.close()
            log_audit(meter_id, "KEY_ROTATION", "FAILED", "Meter not found.")
            return False, f"Meter '{meter_id}' does not exist."

        if meter['status'] == 'REVOKED':
            conn.close()
            log_audit(meter_id, "KEY_ROTATION", "FAILED", "Attempted to rotate key for REVOKED meter.")
            return False, f"Cannot rotate key: Meter '{meter_id}' is REVOKED."

        old_version = meter['key_version']
        new_version = old_version + 1

        try:
            # Generate new RSA parameters
            rsa_data = generate_rsa_keys(bits=key_bits)

            # Mark existing active key as ROTATED
            cursor.execute(
                "UPDATE keys SET status = 'ROTATED' WHERE meter_id = ? AND status = 'ACTIVE'",
                (meter_id,)
            )

            # Insert new active key version
            expiry = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                """INSERT INTO keys 
                   (meter_id, public_exponent, modulus, private_exponent, key_version, expiry_date, status) 
                   VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')""",
                (
                    meter_id,
                    str(rsa_data['e']),
                    str(rsa_data['n']),
                    str(rsa_data['d']),
                    new_version,
                    expiry
                )
            )

            # Update key version on meter record
            cursor.execute(
                "UPDATE meters SET key_version = ? WHERE meter_id = ?",
                (new_version, meter_id)
            )

            conn.commit()

            msg = f"Key rotated successfully from V{old_version} to V{new_version}."
            log_audit(meter_id, "KEY_ROTATION", "SUCCESS", msg)
            conn.close()
            return True, msg

        except Exception as ex:
            conn.rollback()
            conn.close()
            log_audit(meter_id, "KEY_ROTATION", "ERROR", str(ex))
            return False, f"Key rotation error: {str(ex)}"

    @staticmethod
    def revoke_meter_key(meter_id: str, reason: str = "Compromise suspected"):
        """
        Executes Key Revocation for a compromised or decommissioned meter:
        1. Marks meter status as 'REVOKED'.
        2. Marks current active key as 'REVOKED'.
        3. Prevents any future encryption/decryption.
        4. Logs audit trail.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM meters WHERE meter_id = ?", (meter_id,))
        meter = cursor.fetchone()

        if not meter:
            conn.close()
            log_audit(meter_id, "KEY_REVOCATION", "FAILED", "Meter not found.")
            return False, f"Meter '{meter_id}' does not exist."

        try:
            # Mark meter status as REVOKED
            cursor.execute("UPDATE meters SET status = 'REVOKED' WHERE meter_id = ?", (meter_id,))

            # Mark all keys for this meter as REVOKED
            cursor.execute("UPDATE keys SET status = 'REVOKED' WHERE meter_id = ?", (meter_id,))

            conn.commit()

            msg = f"Meter status set to REVOKED. Reason: {reason}."
            log_audit(meter_id, "KEY_REVOCATION", "SUCCESS", msg)
            conn.close()
            return True, msg

        except Exception as ex:
            conn.rollback()
            conn.close()
            log_audit(meter_id, "KEY_REVOCATION", "ERROR", str(ex))
            return False, f"Revocation error: {str(ex)}"

    @staticmethod
    def regenerate_revoked_key(meter_id: str, key_bits: int = 16):
        """Re-establishes an ACTIVE status and generates a fresh RSA key for a revoked meter."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM meters WHERE meter_id = ?", (meter_id,))
        meter = cursor.fetchone()

        if not meter:
            conn.close()
            return False, "Meter not found."

        try:
            rsa_data = generate_rsa_keys(bits=key_bits)
            new_version = meter['key_version'] + 1

            cursor.execute("UPDATE meters SET status = 'ACTIVE', key_version = ? WHERE meter_id = ?", (new_version, meter_id))

            expiry = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                """INSERT INTO keys 
                   (meter_id, public_exponent, modulus, private_exponent, key_version, expiry_date, status) 
                   VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')""",
                (
                    meter_id,
                    str(rsa_data['e']),
                    str(rsa_data['n']),
                    str(rsa_data['d']),
                    new_version,
                    expiry
                )
            )

            conn.commit()
            msg = f"Meter re-activated. Re-established RSA key pair V{new_version}."
            log_audit(meter_id, "KEY_REGENERATION", "SUCCESS", msg)
            conn.close()
            return True, msg

        except Exception as ex:
            conn.rollback()
            conn.close()
            return False, str(ex)

    @staticmethod
    def secure_encrypt_message(meter_id: str, message: str):
        """
        Encrypts a message using targeted meter's active public key.
        Checks meter status and key validity first.
        """
        meter = get_meter(meter_id)
        if not meter:
            log_audit(meter_id, "ENCRYPTION", "FAILED", "Meter not found.")
            return False, "Meter not found.", None

        if meter['status'] == 'REVOKED' or meter['key_status'] != 'ACTIVE':
            log_audit(meter_id, "ENCRYPTION", "DENIED", "Attempted encryption with REVOKED key.")
            return False, "ACCESS DENIED: Meter key is REVOKED or INVALID.", None

        try:
            public_key = (int(meter['public_exponent']), int(meter['modulus']))
            ciphertext_blocks = rsa_encrypt(message, public_key)

            log_audit(meter_id, "ENCRYPTION", "SUCCESS", f"Encrypted {len(message)} char payload.")
            return True, "Encryption successful.", {
                'meter_id': meter_id,
                'public_key': public_key,
                'ciphertext': ciphertext_blocks,
                'key_version': meter['key_version']
            }
        except Exception as ex:
            log_audit(meter_id, "ENCRYPTION", "ERROR", str(ex))
            return False, f"Encryption error: {str(ex)}", None

    @staticmethod
    def secure_decrypt_message(meter_id: str, ciphertext_blocks: list):
        """
        Decrypts ciphertext blocks using targeted meter's active private key.
        Verifies meter and key active status.
        """
        meter = get_meter(meter_id)
        if not meter:
            log_audit(meter_id, "DECRYPTION", "FAILED", "Meter not found.")
            return False, "Meter not found.", None

        if meter['status'] == 'REVOKED' or meter['key_status'] != 'ACTIVE':
            log_audit(meter_id, "DECRYPTION", "DENIED", "Attempted decryption with REVOKED key.")
            return False, "ACCESS DENIED: Meter key is REVOKED or INVALID.", None

        try:
            private_key = (int(meter['private_exponent']), int(meter['modulus']))
            decrypted_text = rsa_decrypt(ciphertext_blocks, private_key)

            log_audit(meter_id, "DECRYPTION", "SUCCESS", "Decryption successful.")
            return True, "Decryption successful.", decrypted_text
        except Exception as ex:
            log_audit(meter_id, "DECRYPTION", "ERROR", str(ex))
            return False, f"Decryption error: {str(ex)}", None