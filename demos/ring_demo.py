import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.ring_pedersen_elgamal import RingPedersenElGamal, StealthAccount

def run_ring_signature_demo():
    print("\n==== Ring Signature + Stealth Address Demo ====\n")
    
    # Initialize the cryptographic system
    crypto = RingPedersenElGamal()
    
    # Create user accounts with stealth capabilities
    alice = StealthAccount(crypto, "Alice")
    bob = StealthAccount(crypto, "Bob")
    charlie = StealthAccount(crypto, "Charlie")
    dave = StealthAccount(crypto, "Dave")
    
    # Initialize balances
    alice.balance = 100
    bob.balance = 50
    charlie.balance = 75
    dave.balance = 25
    
    print("Initial account status:")
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    dave.print_status()
    
    print("\n=== Testing Stealth Transactions ===\n")
    
    # Alice sends funds to Bob using stealth address
    print("Alice sends 30 to Bob using stealth address...")
    amount, R, P = alice.send_funds(bob.get_public_address(), 30)
    bob.receive_funds(amount, R, P)
    time.sleep(1)
    
    # Bob sends funds to Charlie using stealth address
    print("Bob sends 20 to Charlie using stealth address...")
    amount, R, P = bob.send_funds(charlie.get_public_address(), 20)
    charlie.receive_funds(amount, R, P)
    time.sleep(1)
    
    print("\n=== Testing Ring Signatures ===\n")
    
    # Create a ring of public keys
    public_keys = [alice.spend_pk, bob.spend_pk, charlie.spend_pk, dave.spend_pk]
    
    # Alice creates a ring signature (hiding among the group)
    message = "This transaction is approved by one of us"
    signer_idx = 0  # Alice is at index 0
    signature = crypto.generate_ring_signature(message, signer_idx, public_keys, alice.spend_sk)
    
    # Verify the ring signature - should succeed without revealing Alice signed it
    is_valid = crypto.verify_ring_signature(message, public_keys, signature)
    print(f"Ring signature verification: {'✓ Valid' if is_valid else '❌ Invalid'}")
    print(f"Note: Verifier cannot tell which of the {len(public_keys)} members signed the message!")
    
    # Try with wrong message - should fail
    is_valid_wrong = crypto.verify_ring_signature("Different message", public_keys, signature)
    print(f"Wrong message verification: {'✓ Fails as expected' if not is_valid_wrong else '❌ Incorrectly validates'}")
    
    print("\n=== Final Account Status ===\n")
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    dave.print_status()
    
    print("\n==== End of Ring Signature Demo ====")

if __name__ == "__main__":
    run_ring_signature_demo()
