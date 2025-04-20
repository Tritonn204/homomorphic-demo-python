import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.paillier import generate_keypair, encrypt, decrypt, add_encrypted
from constants import PAILLIER_PRIME_P, PAILLIER_PRIME_Q

def run_paillier_demo():
    # Use prime values from constants
    p = PAILLIER_PRIME_P
    q = PAILLIER_PRIME_Q
    pub_key, priv_key = generate_keypair(p, q)
    
    # Test cases
    test_cases = [
        (5, 3),
        (10, 20),
        (100, 200),
        (1000, 2000),
        (12345, 67890),
        (1000000, 2000000),
        (0, 100),
        (999, 1),
        (54321, 12345),
        (7, 7)
    ]
    
    print("\n==== Paillier Homomorphic Encryption Demo ====\n")
    print(f"Using {len(str(p))}-digit primes for cryptographic security\n")
    
    for m1, m2 in test_cases:
        c1 = encrypt(pub_key, m1)
        c2 = encrypt(pub_key, m2)
        c_sum = add_encrypted(pub_key, c1, c2)
        decrypted_sum = decrypt(pub_key, priv_key, c_sum)
        print(f"Test case: {m1} + {m2}")
        print(f"Actual sum: {m1 + m2}")
        print(f"Decrypted sum: {decrypted_sum}")
        print(f"{'✓ Passed' if decrypted_sum == m1 + m2 else '❌ Failed'}\n")
    
    print("==== End of Paillier Demo ====")

if __name__ == "__main__":
    run_paillier_demo()