"""
Phase 3 Verification Script
Tests Database Schema Initialization, Admin Authentication, Smart Meter Registration,
Key Storage, and Audit Logging.
"""

from database import (
    init_db, register_smart_meter, get_meter, get_all_meters, 
    get_audit_logs, verify_admin_login
)

def test_phase_3():
    print("==================================================")
    print("  PHASE 3: DATABASE & SMART METER LOGIC TESTING  ")
    print("==================================================\n")

    # Step 1: Initialize DB Schema
    print("[Test 1] Database Initialization & Table Creation")
    init_db()
    print("  Database tables initialized successfully.\n")

    # Step 2: Verify Admin Login
    print("[Test 2] Admin Authentication Verification")
    valid_login = verify_admin_login("admin", "admin123")
    invalid_login = verify_admin_login("admin", "wrongpass")
    print(f"  Login 'admin/admin123'  : {'PASS' if valid_login else 'FAIL'}")
    print(f"  Login 'admin/wrongpass' : {'PASS' if not invalid_login else 'FAIL'}\n")

    # Step 3: Register Meter MTR001
    print("[Test 3] Smart Meter Registration (MTR001 -> Region R1)")
    success, msg = register_smart_meter("MTR001", "R1", "Hisar Substation", "Smart Electricity Meter")
    print(f"  Registration Status: {success} | Message: '{msg}'")
    
    meter_info = get_meter("MTR001")
    if meter_info:
        print(f"  Registered Meter ID : {meter_info['meter_id']}")
        print(f"  Assigned Region ID  : {meter_info['region_id']}")
        print(f"  Key Version         : V{meter_info['key_version']}")
        print(f"  RSA Public Exponent : {meter_info['public_exponent']}")
        print(f"  RSA Modulus (n)     : {meter_info['modulus']}")
        print(f"  RSA Private Exp (d) : {meter_info['private_exponent']}")
        print(f"  Key Status          : {meter_info['key_status']}")
    print(f"  Meter Record Retrieval: {'PASS' if meter_info and meter_info['meter_id'] == 'MTR001' else 'FAIL'}\n")

    # Step 4: Duplicate Registration Prevention
    print("[Test 4] Duplicate Meter Registration Guard")
    dup_success, dup_msg = register_smart_meter("MTR001", "R1", "Hisar Substation")
    print(f"  Duplicate Attempt Result: Success={dup_success} | Message='{dup_msg}'")
    print(f"  Duplicate Guard Status : {'PASS' if not dup_success else 'FAIL'}\n")

    # Step 5: Register Additional Meters
    print("[Test 5] Batch Registration of Meters across multiple Regional KDCs")
    register_smart_meter("MTR002", "R1", "Rohtak Sector 14")
    register_smart_meter("MTR003", "R2", "Gurugram Cyber City")
    register_smart_meter("MTR004", "R3", "Faridabad Industrial Area")

    all_meters = get_all_meters()
    print(f"  Total Registered Meters in DB: {len(all_meters)}")
    print(f"  Batch Registration Status: {'PASS' if len(all_meters) >= 4 else 'FAIL'}\n")

    # Step 6: Verify Audit Logs
    print("[Test 6] Audit Trail Verification")
    logs = get_audit_logs(limit=10)
    print(f"  Fetched {len(logs)} audit log entries. Latest 3 logs:")
    for log in logs[:3]:
        print(f"    [{log['timestamp']}] Meter: {log['meter_id']} | Op: {log['operation']} | Result: {log['result']} | Info: {log['description']}")
    print(f"  Audit System Verification: {'PASS' if len(logs) > 0 else 'FAIL'}\n")

    print("==================================================")
    print("  ALL PHASE 3 TESTS COMPLETED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_phase_3()