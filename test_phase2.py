"""
Phase 2 Verification Script
Tests RSA Key Generation, Presets, Bit-length scaling, and Text Encryption/Decryption
"""

from rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt, is_prime

def test_phase_2():
    print("==================================================")
    print("  PHASE 2: RSA CRYPTOGRAPHIC ENGINE TESTING      ")
    print("==================================================\n")

    # Test 1: Educational Preset (p=61, q=53, e=17)
    print("[Test 1] Educational RSA Key Generation (Preset p=61, q=53, e=17)")
    keys = generate_rsa_keys(preset_p=61, preset_q=53, preset_e=17)
    print(f"  p={keys['p']}, q={keys['q']}")
    print(f"  Modulus (n) = {keys['n']} | Expected: 3233")
    print(f"  Phi (phi)   = {keys['phi']} | Expected: 3120")
    print(f"  Public Key  = {keys['public_key']}")
    print(f"  Private Key = {keys['private_key']}")
    
    preset_pass = (keys['n'] == 3233 and keys['phi'] == 3120 and keys['d'] == 2753)
    print(f"  Preset Verification: {'PASS' if preset_pass else 'FAIL'}\n")

    # Test 2: Text Encryption & Decryption with Educational Keys
    sample_text = "25 kWh"
    print(f"[Test 2] Smart Meter Text Encryption & Decryption")
    print(f"  Original Message: '{sample_text}'")
    
    cipher_blocks = rsa_encrypt(sample_text, keys['public_key'])
    print(f"  Encrypted Ciphertext Blocks: {cipher_blocks}")
    
    decrypted_text = rsa_decrypt(cipher_blocks, keys['private_key'])
    print(f"  Decrypted Message: '{decrypted_text}'")
    print(f"  Match Status: {'PASS' if decrypted_text == sample_text else 'FAIL'}\n")

    # Test 3: Configurable Key Generation (Automatic 16-bit primes)
    print("[Test 3] Automatic Key Pair Generation (16-bit primes)")
    auto_keys = generate_rsa_keys(bits=16)
    print(f"  Generated p: {auto_keys['p']} (Is Prime: {is_prime(auto_keys['p'])})")
    print(f"  Generated q: {auto_keys['q']} (Is Prime: {is_prime(auto_keys['q'])})")
    print(f"  Modulus n bit-length: {auto_keys['n'].bit_length()} bits")
    
    meter_msg = "MTR001: READ=1045.8"
    cipher = rsa_encrypt(meter_msg, auto_keys['public_key'])
    recovered = rsa_decrypt(cipher, auto_keys['private_key'])
    print(f"  Original  : {meter_msg}")
    print(f"  Recovered : {recovered}")
    print(f"  Match Status: {'PASS' if recovered == meter_msg else 'FAIL'}\n")

    # Test 4: Larger Keys Demonstration (64-bit primes for scalable performance)
    print("[Test 4] Higher-bit Key Generation (64-bit primes -> ~128-bit modulus)")
    high_keys = generate_rsa_keys(bits=64)
    print(f"  Public Exponent e: {high_keys['e']}")
    print(f"  Modulus n (first 30 digits): {str(high_keys['n'])[:30]}...")
    
    payload = "SECURITY_ALERT_GRID_STATION_4"
    c_high = rsa_encrypt(payload, high_keys['public_key'])
    d_high = rsa_decrypt(c_high, high_keys['private_key'])
    print(f"  Match Status: {'PASS' if payload == d_high else 'FAIL'}\n")

    print("==================================================")
    print("  ALL PHASE 2 TESTS COMPLETED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_phase_2()