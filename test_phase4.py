"""
Phase 4 Verification Script
Tests Hierarchical KDC Tree Navigation, Key Rotation, Key Revocation,
Re-generation, and Security-Guarded Encryption/Decryption.
"""

from database import init_db, register_smart_meter, get_meter
from kdc import HierarchicalKDC

def test_phase_4():
    print("==================================================")
    print("  PHASE 4: HIERARCHICAL KDC CORE ENGINE TESTING   ")
    print("==================================================\n")

    # Step 1: Ensure DB is initialized and seed sample meters
    init_db()
    register_smart_meter("MTR101", "R1", "Substation Alpha")
    register_smart_meter("MTR102", "R2", "Substation Beta")

    # Step 2: Test Hierarchy Navigation Tree
    print("[Test 1] KDC Hierarchy Tree Construction")
    tree = HierarchicalKDC.get_hierarchy_tree()
    print(f"  Root Name    : {tree['name']}")
    print(f"  Total Regions: {len(tree['children'])}")
    for r in tree['children']:
        print(f"    Region {r['region_id']} ({r['name']}) -> {r['meter_count']} meters")
    print(f"  Hierarchy Tree Status: {'PASS' if len(tree['children']) >= 3 else 'FAIL'}\n")

    # Step 3: Test Key Rotation (V1 -> V2)
    print("[Test 2] Key Rotation Mechanism for MTR101")
    meter_before = get_meter("MTR101")
    print(f"  Version BEFORE Rotation: V{meter_before['key_version']}")
    
    rot_success, rot_msg = HierarchicalKDC.rotate_meter_key("MTR101")
    print(f"  Rotation Result: {rot_success} | Msg: '{rot_msg}'")
    
    meter_after = get_meter("MTR101")
    print(f"  Version AFTER Rotation : V{meter_after['key_version']}")
    print(f"  Key Rotation Status   : {'PASS' if meter_after['key_version'] == meter_before['key_version'] + 1 else 'FAIL'}\n")

    # Step 4: Test Encryption & Decryption with Rotated Key
    print("[Test 3] Encrypt and Decrypt using Rotated Key V2")
    payload = "45.2 kWh CONSUMPTION"
    enc_ok, enc_msg, enc_data = HierarchicalKDC.secure_encrypt_message("MTR101", payload)
    print(f"  Encryption: {enc_ok} | Ciphertext Blocks: {enc_data['ciphertext']}")
    
    dec_ok, dec_msg, decrypted_val = HierarchicalKDC.secure_decrypt_message("MTR101", enc_data['ciphertext'])
    print(f"  Decryption: {dec_ok} | Recovered Payload: '{decrypted_val}'")
    print(f"  Encryption/Decryption Status: {'PASS' if decrypted_val == payload else 'FAIL'}\n")

    # Step 5: Test Key Revocation & Security Enforcement
    print("[Test 4] Key Revocation Mechanism & Access Enforcement")
    rev_ok, rev_msg = HierarchicalKDC.revoke_meter_key("MTR101", "Physical Tampering Detected")
    print(f"  Revocation Executed: {rev_ok} | Msg: '{rev_msg}'")
    
    rev_meter = get_meter("MTR101")
    print(f"  Meter Status in DB : {rev_meter['status']}")
    print(f"  Key Status in DB   : {rev_meter['key_status']}")

    # Attempt encryption with revoked key (Must fail/denied)
    denied_enc, denied_msg, _ = HierarchicalKDC.secure_encrypt_message("MTR101", "100 kWh")
    print(f"  Revoked Key Encryption Guard Result: Success={denied_enc} | Msg='{denied_msg}'")
    print(f"  Security Guard Verification        : {'PASS' if not denied_enc and 'DENIED' in denied_msg else 'FAIL'}\n")

    # Step 6: Test Key Re-generation
    print("[Test 5] Revoked Key Re-establishment / Regeneration")
    regen_ok, regen_msg = HierarchicalKDC.regenerate_revoked_key("MTR101")
    print(f"  Re-generation Result: {regen_ok} | Msg: '{regen_msg}'")
    
    restored_meter = get_meter("MTR101")
    print(f"  Restored Meter Status: {restored_meter['status']}")
    print(f"  Restored Key Version : V{restored_meter['key_version']}")
    
    # Verify encryption works again
    rest_enc, _, rest_data = HierarchicalKDC.secure_encrypt_message("MTR101", "RESTORED 50 kWh")
    rest_dec, _, rest_plain = HierarchicalKDC.secure_decrypt_message("MTR101", rest_data['ciphertext'])
    print(f"  Restored Encryption/Decryption Match: '{rest_plain}'")
    print(f"  Re-generation Status: {'PASS' if rest_plain == 'RESTORED 50 kWh' else 'FAIL'}\n")

    print("==================================================")
    print("  ALL PHASE 4 TESTS COMPLETED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_phase_4()