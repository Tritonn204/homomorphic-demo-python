import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zkp.zk_pedersen_elgamal import ZKPedersenElGamal, ZKAccount

def run_zk_demo():
    print("\n==== Zero-Knowledge Proof Demo ====\n")
    print("Initializing ZK-enabled cryptographic system...")
    
    # Create a new instance with a smaller curve for demo purposes
    zk_system = ZKPedersenElGamal(curve_name='secp192r1')
    
    # Generate lookup table for fast decryption (limit to 1000 for demo)
    zk_system.generate_value_table(max_range=1000)
    
    # Create accounts
    alice = ZKAccount(zk_system, "Alice")
    bob = ZKAccount(zk_system, "Bob")
    charlie = ZKAccount(zk_system, "Charlie")
    
    print("\nInitializing accounts with starting balances...")
    alice.deposit(500)
    bob.deposit(300)
    charlie.deposit(200)
    
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    
    print("\n=== Testing Private ZK Transactions ===\n")
    
    print("Alice sends 100 to Bob with privacy...")
    alice.send(bob, 100)
    time.sleep(1)
    
    print("Bob sends 50 to Charlie with privacy...")
    bob.send(charlie, 50)
    time.sleep(1)
    
    print("Charlie sends 25 back to Alice with privacy...")
    charlie.send(alice, 25)
    time.sleep(1)
    
    print("\n=== Testing Range Proofs ===\n")
    
    # Alice generates a range proof that she has between 300-600 without revealing actual balance
    try:
        balance_proof = zk_system.range_proof(alice.balance, 300, 600)
        is_valid = zk_system.verify_range_proof(balance_proof)
        print(f"Alice's balance range proof verification: {'✓ Valid' if is_valid else '❌ Invalid'}")
        print(f"Verifier only knows Alice's balance is in range [300, 600], not the exact value!")
    except ValueError as e:
        print(f"Range proof failed: {e}")
    
    print("\n=== Final Account Status ===\n")
    
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    
    print("\n==== End of Zero-Knowledge Proof Demo ====")

if __name__ == "__main__":
    run_zk_demo()
