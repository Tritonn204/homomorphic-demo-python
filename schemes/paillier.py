import random
import sys
import os

# Add the parent directory to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.math_helpers import lcm, L

def generate_keypair(p, q):
    """Generate a keypair for the Paillier cryptosystem.
    
    Args:
        p, q: Large prime numbers
        
    Returns:
        tuple: ((n, g), (lambda_, mu)) - public key and private key
    """
    n = p * q
    g = n + 1
    lambda_ = lcm(p - 1, q - 1)
    mu = pow(lambda_, -1, n)
    return ((n, g), (lambda_, mu))

def encrypt(pub_key, m):
    """Encrypt a message using Paillier encryption.
    
    Args:
        pub_key: Public key (n, g)
        m: Message to encrypt
    
    Returns:
        int: Encrypted ciphertext
    """
    n, g = pub_key
    r = random.randint(1, n - 1)
    return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

def decrypt(pub_key, priv_key, c):
    """Decrypt a Paillier ciphertext.
    
    Args:
        pub_key: Public key (n, g)
        priv_key: Private key (lambda_, mu)
        c: Ciphertext to decrypt
    
    Returns:
        int: Decrypted message
    """
    n, _ = pub_key
    lambda_, mu = priv_key
    return (L(pow(c, lambda_, n * n), n) * mu) % n

def add_encrypted(pub_key, c1, c2):
    """Add two encrypted values homomorphically.
    
    Args:
        pub_key: Public key (n, g)
        c1, c2: Encrypted values
    
    Returns:
        int: Encrypted sum
    """
    n, _ = pub_key
    return (c1 * c2) % (n * n)

def multiply_constant(pub_key, c, k):
    """Multiply an encrypted value by a constant.
    
    Args:
        pub_key: Public key (n, g)
        c: Encrypted value
        k: Constant factor
    
    Returns:
        int: Encrypted product
    """
    n, _ = pub_key
    return pow(c, k, n * n)
