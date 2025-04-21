import random
import hashlib
from tinyec import registry
from tinyec.ec import Point
from tqdm import tqdm

# Import constants
from constants import (
    TABLE_MAX, 
    PEDERSEN_H_GENERATOR_SEED, 
    DEFAULT_CURVE, 
    DEFAULT_ACCOUNT_NAME_PREFIX,
    RANDOM_ACCOUNT_ID_MIN,
    RANDOM_ACCOUNT_ID_MAX
)

class PedersenElGamal:
    def __init__(self, curve_name=DEFAULT_CURVE):
        # System setup
        self.curve = registry.get_curve(curve_name)
        self.G = self.curve.g
        self.q = self.curve.field.n
        
        # Create second generator H for Pedersen commitments
        h_seed = hashlib.sha256(PEDERSEN_H_GENERATOR_SEED).digest()
        h_value = int.from_bytes(h_seed, byteorder="big") % self.q
        self.H = h_value * self.G
        self.LOOKUP_G = {}
        
        # For simplicity: Tables for small values to help with "discrete log" problem
        for i in tqdm(range(TABLE_MAX), desc="Building value table"):
            point = i * self.G
            self.LOOKUP_G[i] = point.x  # Simple lookup by x-coordinate
    
    def pedersen_commit(self, value, blinding_factor):
        """Create a Pedersen commitment to a value."""
        return value * self.G + blinding_factor * self.H
    
    def twisted_elgamal_keygen(self):
        """Generate a keypair for Twisted ElGamal encryption."""
        sk = random.randint(1, self.q-1)
        pk = sk * self.G
        return (sk, pk)
    
    def twisted_elgamal_encrypt(self, amount, recipient_pk, randomness=None):
        """Encrypt an amount using Twisted ElGamal encryption."""
        if randomness is None:
            randomness = random.randint(1, self.q-1)
        return (randomness * self.G, amount * self.G + randomness * recipient_pk)
    
    def twisted_elgamal_decrypt(self, ciphertext, sk):
        """Decrypt a Twisted ElGamal ciphertext."""
        c1, c2 = ciphertext
        amount_point = c2 - sk * c1
        
        # In a real system, we might use more sophisticated methods to extract amount
        # This is a simplified approach for small values
        for i in range(TABLE_MAX):
            if self.LOOKUP_G[i] == amount_point.x:
                return i
        return None  # Cannot determine exact amount

    def print_system_info(self):
        """Print information about the cryptographic system setup."""
        print(f"System setup complete:")
        print(f"Curve: {self.curve.name}")
        print(f"G: ({self.G.x}, {self.G.y})")
        print(f"H: ({self.H.x}, {self.H.y})\n")

class Account:
    def __init__(self, crypto_system, name=None):
        self.crypto_system = crypto_system
        self.name = name if name else f"{DEFAULT_ACCOUNT_NAME_PREFIX}{random.randint(RANDOM_ACCOUNT_ID_MIN, RANDOM_ACCOUNT_ID_MAX)}"
        self.sk, self.pk = crypto_system.twisted_elgamal_keygen()
        self.balance = 0
        self.encrypted_balance = None
        self.commitment = None
        self.blinding_factor = None
        self.transaction_history = []
    
    def deposit(self, amount):
        """Deposit an amount and update balance with commitments and encryption."""
        self.balance += amount
        self.blinding_factor = random.randint(1, self.crypto_system.q-1)
        self.commitment = self.crypto_system.pedersen_commit(self.balance, self.blinding_factor)
        self.encrypted_balance = self.crypto_system.twisted_elgamal_encrypt(self.balance, self.pk)
        self.transaction_history.append(f"Deposit: +{amount}")
    
    def transfer(self, recipient, amount):
        """Transfer encrypted amount to recipient."""
        if amount > self.balance:
            print(f"Insufficient funds: {self.balance} < {amount}")
            return False
        
        # Update sender's state
        self.balance -= amount
        self.blinding_factor = random.randint(1, self.crypto_system.q-1)
        self.commitment = self.crypto_system.pedersen_commit(self.balance, self.blinding_factor)
        self.encrypted_balance = self.crypto_system.twisted_elgamal_encrypt(self.balance, self.pk)
        self.transaction_history.append(f"Transfer: -{amount} to {recipient.name}")
        
        # Update recipient's state
        recipient.balance += amount
        recipient.blinding_factor = random.randint(1, self.crypto_system.q-1)
        recipient.commitment = self.crypto_system.pedersen_commit(recipient.balance, recipient.blinding_factor)
        recipient.encrypted_balance = self.crypto_system.twisted_elgamal_encrypt(recipient.balance, recipient.pk)
        recipient.transaction_history.append(f"Received: +{amount} from {self.name}")
        
        print(f"Transferred {amount} from {self.name} to {recipient.name}")
        return True
    
    def verify_balance(self):
        """Verify that the encrypted balance decrypts correctly."""
        decrypted = self.crypto_system.twisted_elgamal_decrypt(self.encrypted_balance, self.sk)
        if decrypted == self.balance:
            print(f"{self.name}: Balance integrity verified ✓")
            return True
        else:
            print(f"{self.name}: Balance integrity ERROR!")
            return False
    
    def print_status(self):
        """Print account status with commitment and encrypted values."""
        print(f"\n--- {self.name} Status ---")
        print(f"Balance: {self.balance}")
        print(f"Commitment: ({self.commitment.x}, {self.commitment.y})")
        c1, c2 = self.encrypted_balance
        print(f"Encrypted Balance: ")
        print(f"  C1: ({c1.x}, {c1.y})")
        print(f"  C2: ({c2.x}, {c2.y})")
        print(f"Recent Transactions:")
        for txn in self.transaction_history[-TX_HISTORY_DISPLAY_COUNT:]:
            print(f"  {txn}")
        print()