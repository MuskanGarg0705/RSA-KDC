"""
RSA Cryptographic Engine Module
Implements key generation, text byte packing/unpacking, and encryption/decryption.
Designed for Academic Demonstration - Scalable KDC RSA System
"""

import secrets
from extended_euclid import gcd, mod_inverse, mod_pow

# Pre-computed small primes for fast trial division
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151
]


def is_prime_trial_division(n: int) -> bool:
    """Checks primality using deterministic trial division (ideal for small numbers)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    
    d = 137
    while d * d <= n:
        if n % d == 0 or n % (d + 2) == 0:
            return False
        d += 6
    return True


def is_prime_miller_rabin(n: int, k: int = 8) -> bool:
    """
    Probabilistic Miller-Rabin primality test for larger numbers.
    k = number of rounds (accuracy = 1 - 4^(-k))
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False

    return True


def is_prime(n: int) -> bool:
    """Unified primality checker."""
    if n < 1000:
        return is_prime_trial_division(n)
    return is_prime_miller_rabin(n)


def generate_prime(bits: int) -> int:
    """Generates a random prime number of specified bit length."""
    while True:
        # Ensure highest bit and lowest bit are set (odd number)
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def generate_rsa_keys(bits: int = 16, preset_p: int = None, preset_q: int = None, preset_e: int = 65537):
    """
    Generates RSA Key Pair.
    
    Args:
        bits: Bit size of primes p and q (e.g., 16 for demo, 512 for production mode).
        preset_p: Optional prime p for manual educational test cases (e.g., 61).
        preset_q: Optional prime q for manual educational test cases (e.g., 53).
        preset_e: Public exponent (default 65537 or 17 for small demo).
        
    Returns:
        dict containing public key, private key, p, q, n, phi, e, d, and euclidean steps.
    """
    if preset_p and preset_q:
        p, q = preset_p, preset_q
    else:
        # Generate two distinct prime numbers
        p = generate_prime(bits)
        q = generate_prime(bits)
        while p == q:
            q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e
    e = preset_e
    if gcd(e, phi) != 1:
        # Fallback to small odd primes if preset_e is not coprime to phi
        possible_e = [17, 65537, 3, 5, 7]
        e_found = False
        for candidate_e in possible_e:
            if candidate_e < phi and gcd(candidate_e, phi) == 1:
                e = candidate_e
                e_found = True
                break
        
        if not e_found:
            e = 3
            while gcd(e, phi) != 1:
                e += 2

    # Calculate private exponent d using Extended Euclidean Algorithm
    d, steps = mod_inverse(e, phi)

    return {
        'public_key': (e, n),
        'private_key': (d, n),
        'p': p,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'steps': steps
    }


def text_to_blocks(message: str, n: int) -> list:
    """
    Converts text message string into integer blocks small enough for modulus n.
    Block size in bytes is determined by max bytes that fit into n.
    """
    # Calculate safe byte chunk size (at least 1 byte)
    max_bytes = max(1, (n.bit_length() - 1) // 8)
    msg_bytes = message.encode('utf-8')
    
    blocks = []
    for i in range(0, len(msg_bytes), max_bytes):
        chunk = msg_bytes[i:i + max_bytes]
        block_int = int.from_bytes(chunk, byteorder='big')
        if block_int >= n:
            raise ValueError(f"Block value {block_int} exceeds or equals modulus {n}. Key size too small.")
        blocks.append(block_int)
        
    return blocks


def blocks_to_text(blocks: list, n: int) -> str:
    """Converts decrypted integer blocks back into string text."""
    max_bytes = max(1, (n.bit_length() - 1) // 8)
    msg_bytes = bytearray()
    
    for block in blocks:
        # Determine necessary byte length for this integer
        length = (block.bit_length() + 7) // 8
        if length == 0:
            length = 1
        chunk = block.to_bytes(length, byteorder='big')
        msg_bytes.extend(chunk)
        
    return msg_bytes.decode('utf-8', errors='ignore')


def rsa_encrypt(message: str, public_key: tuple) -> list:
    """
    Encrypts a plaintext message using RSA Public Key (e, n).
    Returns list of ciphered integer blocks.
    """
    e, n = public_key
    blocks = text_to_blocks(message, n)
    ciphertext_blocks = [mod_pow(block, e, n) for block in blocks]
    return ciphertext_blocks


def rsa_decrypt(ciphertext_blocks: list, private_key: tuple, n_modulus: int = None) -> str:
    """
    Decrypts ciphertext blocks using RSA Private Key (d, n).
    Returns recovered plaintext string.
    """
    if isinstance(private_key, tuple):
        d, n = private_key
    else:
        d = private_key
        n = n_modulus

    decrypted_blocks = [mod_pow(c, d, n) for c in ciphertext_blocks]
    return blocks_to_text(decrypted_blocks, n)