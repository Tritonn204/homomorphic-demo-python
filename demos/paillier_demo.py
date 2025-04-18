import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.paillier import generate_keypair, encrypt, decrypt, add_encrypted

def run_paillier_demo():
    # Example prime values from original code
    p = 164582266122523438021796530718520447716264786386032139428492675898640548395244104114646521848386833120382750579731761970300219222952828459073248723805158721561691497204529864185193361396768084851011164401992951340942693585099212705096574206856288010548587877692918763753382364407990772475123244873470905810041
    q = 172084174117479480555949609630075409379951658357856832848305708116588064310618618361140542244767058717047624932367347152210820790338519632916344512450660693039101064646179881617199973657049854477318136730519323268184227563086883207528472644656875192552855741305729888628171268187791140343758830697165240750803
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
