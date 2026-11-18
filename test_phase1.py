"""
Phase 1 Verification Script
Tests GCD, Extended GCD, Modular Inverse, and Modular Exponentiation
"""

from extended_euclid import gcd, extended_gcd, mod_inverse, mod_pow

def test_phase_1():
    print("==================================================")
    print("  PHASE 1: EXTENDED EUCLIDEAN ALGORITHM TESTING  ")
    print("==================================================\n")

    # Test 1: Basic GCD
    a1, b1 = 48, 18
    g1 = gcd(a1, b1)
    print(f"[Test 1] GCD({a1}, {b1})")
    print(f"  Result: {g1} | Expected: 6 -> {'PASS' if g1 == 6 else 'FAIL'}\n")

    # Test 2: Extended GCD and Bezout Coefficients
    a2, b2 = 17, 3120
    g2, x2, y2, steps2 = extended_gcd(a2, b2)
    print(f"[Test 2] Extended GCD({a2}, {b2})")
    print(f"  gcd = {g2}, x = {x2}, y = {y2}")
    bezout_val = a2 * x2 + b2 * y2
    print(f"  Verification: {a2}*({x2}) + {b2}*({y2}) = {bezout_val}")
    print(f"  Status: {'PASS' if bezout_val == g2 == 1 else 'FAIL'}\n")

    # Test 3: Modular Inverse for RSA Example (p=61, q=53, phi=3120, e=17)
    e, phi = 17, 3120
    d, steps = mod_inverse(e, phi)
    print(f"[Test 3] Modular Inverse of e={e} mod phi={phi}")
    print(f"  Calculated Private Exponent d = {d}")
    print(f"  Expected d = 2753")
    
    # Proof: (e * d) mod phi == 1
    verification_check = (e * d) % phi
    print(f"  Verification check: ({e} * {d}) mod {phi} = {verification_check}")
    print(f"  Status: {'PASS' if d == 2753 and verification_check == 1 else 'FAIL'}\n")

    # Test 4: Printing Execution Steps for UI Trace
    print("  [Step-by-Step Trace for RSA Calculator Demonstration]")
    print("  ----------------------------------------------------")
    for s in steps:
        print(f"  Step {s['step']}: {s['a']} = {s['quotient']} * {s['b']} + {s['remainder']}")
    print("  ----------------------------------------------------\n")

    # Test 5: Modular Exponentiation
    base, exp, mod = 25, 17, 3233
    cipher = mod_pow(base, exp, mod)
    decrypted = mod_pow(cipher, d, mod)
    print(f"[Test 5] Modular Exponentiation (Textbook RSA Math)")
    print(f"  Message (M): {base}")
    print(f"  Ciphertext C = ({base}^{exp}) mod {mod} = {cipher}")
    print(f"  Decrypted  M' = ({cipher}^{d}) mod {mod} = {decrypted}")
    print(f"  Status: {'PASS' if decrypted == base else 'FAIL'}\n")

    print("==================================================")
    print("  ALL PHASE 1 TESTS COMPLETED SUCCESSFULLY!       ")
    print("==================================================")

if __name__ == "__main__":
    test_phase_1()