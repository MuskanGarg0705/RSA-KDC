"""
Extended Euclidean Algorithm and Modular Arithmetic Module
Designed for Academic Demonstration - Scalable KDC RSA System
"""

def gcd(a: int, b: int) -> int:
    """
    Computes the Greatest Common Divisor (GCD) of two numbers using 
    the standard Euclidean Algorithm.
    
    Formula: gcd(a, b) = gcd(b, a mod b) until b == 0
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """
    Computes the Extended Euclidean Algorithm.
    Returns a tuple: (g, x, y, steps)
    where:
        g = gcd(a, b)
        x, y are integers satisfying: a*x + b*y = g
        steps is a list of intermediate execution dictionaries for UI visualization.
    """
    steps = []
    
    # Iterative implementation maintaining coefficients
    # x0, y0 represent coefficients for current 'a'
    # x1, y1 represent coefficients for current 'b'
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    
    orig_a, orig_b = a, b
    
    step_num = 1
    while b != 0:
        q = a // b
        r = a % b
        
        steps.append({
            'step': step_num,
            'a': a,
            'b': b,
            'quotient': q,
            'remainder': r,
            'x0': x0, 'x1': x1,
            'y0': y0, 'y1': y1
        })
        
        # Update a and b
        a, b = b, r
        
        # Update Bezout coefficients
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
        
        step_num += 1

    steps.append({
        'step': step_num,
        'a': a,
        'b': 0,
        'quotient': 0,
        'remainder': 0,
        'x0': x0, 'x1': x1,
        'y0': y0, 'y1': y1
    })

    return a, x0, y0, steps


def mod_inverse(e: int, phi: int):
    """
    Calculates the Modular Multiplicative Inverse of 'e' modulo 'phi'
    using the Extended Euclidean Algorithm.
    
    Returns:
        (d, steps) where e * d ≡ 1 (mod phi)
    Raises:
        ValueError if inverse does not exist (i.e., gcd(e, phi) != 1)
    """
    g, x, y, steps = extended_gcd(e, phi)
    
    if g != 1:
        raise ValueError(f"Modular inverse does not exist because gcd({e}, {phi}) = {g} != 1")
    
    # Ensure d is positive within range [0, phi - 1]
    d = (x % phi + phi) % phi
    return d, steps


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Performs Efficient Modular Exponentiation: (base^exponent) % modulus
    Using the Square-and-Multiply method (Binary Exponentiation).
    O(log(exponent)) time complexity.
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply base with result
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        
        # exponent must be even now
        exponent = exponent >> 1  # exponent = exponent // 2
        base = (base * base) % modulus
        
    return result