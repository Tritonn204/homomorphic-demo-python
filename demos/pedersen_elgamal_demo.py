import sys
import os
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.pedersen_elgamal import PedersenElGamal, Account

def run_pedersen_elgamal_demo():
    print("\n==== Pedersen Commitment + Twisted ElGamal Encryption Demo ====\n")
    
    # Initialize the cryptographic system
    crypto = PedersenElGamal()
    crypto.print_system_info()
    
    # Create accounts
    alice = Account(crypto, "Alice")
    bob = Account(crypto, "Bob")
    charlie = Account(crypto, "Charlie")
    
    print("Creating accounts and testing initial deposits...")
    
    # Initial deposits
    alice.deposit(50)
    bob.deposit(30)
    charlie.deposit(100)
    
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    
    print("\n=== Testing Account Verification ===\n")
    
    # Verify that encryption is working correctly
    alice.verify_balance()
    bob.verify_balance()
    charlie.verify_balance()
    
    print("\n=== Testing Transactions ===\n")
    
    print("Alice sends 20 to Bob...")
    alice.transfer(bob, 20)
    time.sleep(1)
    
    print("Bob sends 15 to Charlie...")
    bob.transfer(charlie, 15)
    time.sleep(1)
    
    print("Charlie sends 30 to Alice...")
    charlie.transfer(alice, 30)
    time.sleep(1)
    
    print("\n=== Final Account Status ===\n")
    
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    
    print("\n=== Verifying final balances ===\n")
    alice.verify_balance()
    bob.verify_balance()
    charlie.verify_balance()
    
    print("\n==== End of Pedersen ElGamal Demo ====")

if __name__ == "__main__":
    run_pedersen_elgamal_demo()
