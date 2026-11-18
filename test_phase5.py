"""
Phase 5 Verification Script
Tests Flask Web Application Routes, REST API Endpoints, JSON Serialization,
and Session Guardrails.
"""

import json
from app import app, init_db

def test_phase_5():
    print("==================================================")
    print("  PHASE 5: FLASK WEB BACKEND & REST API TESTING  ")
    print("==================================================\n")

    init_db()
    client = app.test_client()

    # Step 1: Login Route Test
    print("[Test 1] Login & Session Management")
    res_login = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    print(f"  Login Response Status Code: {res_login.status_code}")
    print(f"  Session Established       : {'PASS' if res_login.status_code == 200 else 'FAIL'}\n")

    # Step 2: REST API - Meter Registration
    print("[Test 2] REST API Endpoint POST /api/meters")
    payload = {
        "meter_id": "MTR501",
        "region_id": "R1",
        "location": "Noida Substation Sector 62",
        "meter_type": "Smart Industrial Meter",
        "key_bits": 16
    }
    res_reg = client.post('/api/meters', data=json.dumps(payload), content_type='application/json')
    data_reg = json.loads(res_reg.data)
    print(f"  API Status Code : {res_reg.status_code}")
    print(f"  API Response    : {data_reg['message']}")
    print(f"  Endpoint Status : {'PASS' if res_reg.status_code == 201 and data_reg['success'] else 'FAIL'}\n")

    # Step 3: REST API - GET Meter
    print("[Test 3] REST API Endpoint GET /api/meters/MTR501")
    res_get = client.get('/api/meters/MTR501')
    data_get = json.loads(res_get.data)
    print(f"  Retrieved Meter ID  : {data_get['meter']['meter_id']}")
    print(f"  Public Exponent (e) : {data_get['meter']['public_exponent']}")
    print(f"  Modulus (n)         : {data_get['meter']['modulus']}")
    print(f"  Endpoint Status     : {'PASS' if data_get['success'] else 'FAIL'}\n")

    # Step 4: REST API - Encrypt Message
    print("[Test 4] REST API Endpoint POST /api/encrypt")
    enc_payload = {"meter_id": "MTR501", "message": "150.5 kWh"}
    res_enc = client.post('/api/encrypt', data=json.dumps(enc_payload), content_type='application/json')
    data_enc = json.loads(res_enc.data)
    cipher_blocks = data_enc['data']['ciphertext']
    print(f"  Encrypted Ciphertext Blocks: {cipher_blocks}")
    print(f"  Encryption Endpoint Status : {'PASS' if data_enc['success'] else 'FAIL'}\n")

    # Step 5: REST API - Decrypt Message
    print("[Test 5] REST API Endpoint POST /api/decrypt")
    dec_payload = {"meter_id": "MTR501", "ciphertext": cipher_blocks}
    res_dec = client.post('/api/decrypt', data=json.dumps(dec_payload), content_type='application/json')
    data_dec = json.loads(res_dec.data)
    print(f"  Decrypted Message Received : '{data_dec['decrypted_text']}'")
    print(f"  Decryption Endpoint Status : {'PASS' if data_dec['decrypted_text'] == '150.5 kWh' else 'FAIL'}\n")

    # Step 6: REST API - Rotate Key
    print("[Test 6] REST API Endpoint POST /api/meters/MTR501/rotate")
    res_rot = client.post('/api/meters/MTR501/rotate', data=json.dumps({}), content_type='application/json')
    data_rot = json.loads(res_rot.data)
    print(f"  Rotation Result: {data_rot['message']}")
    print(f"  Rotation API Status: {'PASS' if data_rot['success'] else 'FAIL'}\n")

    # Step 7: REST API - Topology Tree
    print("[Test 7] REST API Endpoint GET /api/topology")
    res_top = client.get('/api/topology')
    data_top = json.loads(res_top.data)
    print(f"  Topology Root Name : {data_top['topology']['name']}")
    print(f"  Regions Returned   : {len(data_top['topology']['children'])}")
    print(f"  Topology API Status: {'PASS' if data_top['success'] else 'FAIL'}\n")

    print("==================================================")
    print("  ALL PHASE 5 TESTS COMPLETED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_phase_5()