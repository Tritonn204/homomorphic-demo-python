from math import gcd

def lcm(a, b):
    """Compute the Least Common Multiple of a and b."""
    return abs(a * b) // gcd(a, b)

def L(x, n):
    """Compute the L-function used in Paillier cryptosystem."""
    return (x - 1) // n

def safe_equals(x, y):
    try:
        return int(str(x).strip()) == int(str(y).strip())
    except Exception:
        return False