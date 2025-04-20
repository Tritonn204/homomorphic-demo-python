import random
import sympy
from math import gcd

from constants import PRIME_GEN_MIN_FACTOR, PRIME_GEN_ATTEMPTS, PRIME_BIT_LENGTHS

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def L(x, n):
    return (x - 1) // n

def test_key_generation(bit_length):
    try:
        # Generate primes in the upper-middle part of the range using the constant factor
        lower_bound = int(2**(bit_length-1) + (2**bit_length - 2**(bit_length-1)) * PRIME_GEN_MIN_FACTOR)
        upper_bound = 2**bit_length - 1
        
        p = sympy.randprime(lower_bound, upper_bound)
        q = sympy.randprime(lower_bound, upper_bound)
        while p == q:  # Ensure p and q are different
            q = sympy.randprime(lower_bound, upper_bound)
            
        n = p * q
        lambda_ = lcm(p - 1, q - 1)
        mu = pow(lambda_, -1, n)  # This may raise ValueError if not invertible
        
        # Test a simple encryption/decryption
        g = n + 1
        pub_key = (n, g)
        priv_key = (lambda_, mu)
        
        m = 42  # Test message
        r = random.randint(1, n - 1)
        c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
        decrypted = (L(pow(c, lambda_, n * n), n) * mu) % n
        
        if decrypted == m:
            return True, p, q
        return False, None, None
    except Exception as e:
        return False, None, None, str(e)

def find_working_primes_by_size():
    print("Finding working prime pairs by bit length:")
    print("-----------------------------------------")
    successful_primes = {}
    
    for bit_length in PRIME_BIT_LENGTHS:
        print(f"Testing {bit_length}-bit primes...", end=" ")
        
        # Try up to the configured number of attempts for each bit length
        for attempt in range(PRIME_GEN_ATTEMPTS):
            result = test_key_generation(bit_length)
            
            if isinstance(result, tuple) and len(result) >= 3:
                success, p, q = result
                if not success:
                    if attempt == PRIME_GEN_ATTEMPTS - 1:  # Last attempt
                        print(f"Failed: ")
                    continue
            else:
                success, p, q = result
                
            if success:
                successful_primes[bit_length] = (p, q)
                print(f"Success!")
                print(f"p = {p}")
                print(f"q = {q}")
                print(f"Approximate decimal digits: {len(str(p))}")
                print("-----------------------------------------")
                break
            elif attempt == PRIME_GEN_ATTEMPTS - 1:  # Last attempt
                print("Failed after multiple attempts")
    
    return successful_primes

# Run the function
if __name__ == "__main__":
    working_primes = find_working_primes_by_size()
    
    print("\nSummary of Working Prime Sizes:")
    for bit_length, (p, q) in sorted(working_primes.items()):
        print(f"{bit_length}-bit: Primes of approximately {len(str(p))} digits")
        
    print("\nSelect a bit size from the summary above for your implementation.")