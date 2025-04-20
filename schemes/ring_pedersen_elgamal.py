import random
import hashlib
import time
from tinyec import registry
from tinyec.ec import Point
from .pedersen_elgamal import PedersenElGamal

# Import constants
from constants import (
    DEFAULT_CURVE,
    DEFAULT_STEALTH_ACCOUNT_NAME_PREFIX,
    RANDOM_ACCOUNT_ID_MIN,
    RANDOM_ACCOUNT_ID_MAX,
    TX_HISTORY_DISPLAY_COUNT
)

class RingPedersenElGamal(PedersenElGamal):
    def __init__(self, curve_name=DEFAULT_CURVE):
        super().__init__(curve_name)
    
    def generate_stealth_address(self, recipient_view_pk, recipient_spend_pk):
        """Generate one-time stealth address for sending funds privately."""
        r = random.randint(1, self.q-1)  # One-time random value
        R = r * self.G  # Public value sent with transaction
        
        # Shared secret - only recipient can compute this
        shared_secret_point = r * recipient_view_pk
        shared_secret = shared_secret_point.x.to_bytes((shared_secret_point.x.bit_length() + 7) // 8, byteorder='big')
        
        # Derive the one-time address
        h = int.from_bytes(hashlib.sha256(shared_secret).digest(), byteorder='big') % self.q
        P = h * self.G + recipient_spend_pk
        
        return (R, P)  # Send these with transaction
    
    def recover_stealth_address(self, R, P, view_sk, spend_pk):
        """Recipient recovers funds sent to stealth address."""
        # Recompute shared secret
        shared_secret_point = view_sk * R
        shared_secret = shared_secret_point.x.to_bytes((shared_secret_point.x.bit_length() + 7) // 8, byteorder='big')
        
        # Derive h value
        h = int.from_bytes(hashlib.sha256(shared_secret).digest(), byteorder='big') % self.q
        
        # Check if P = h*G + spend_pk
        expected_P = h * self.G + spend_pk
        
        return (expected_P.x == P.x and expected_P.y == P.y)
    
    def generate_ring_signature(self, message, signer_idx, public_keys, private_key):
        """Generate a ring signature that hides the true signer among the public keys."""
        n = len(public_keys)
        
        if signer_idx >= n:
            raise ValueError("Signer index must be less than number of public keys")
        
        # Compute message hash
        message_bytes = message.encode() if isinstance(message, str) else message
        message_hash = int.from_bytes(hashlib.sha256(message_bytes).digest(), byteorder='big') % self.q
        
        # Initialize random values and compute c_next
        c = [0] * n
        s = [0] * n
        
        # Choose random value for the signer
        k = random.randint(1, self.q-1)
        
        # Start with the signer, compute their commitment
        signer_point = k * self.G
        
        # Generate random values for all other participants
        for i in range(n):
            if i != signer_idx:
                s[i] = random.randint(1, self.q-1)
                c[(i+1) % n] = int.from_bytes(hashlib.sha256((str(i) + str(message_hash) + 
                                                             str((s[i] * self.G + c[i] * public_keys[i]).x)).encode()).digest(), byteorder='big') % self.q
        
        # Complete the ring for the signer
        c[(signer_idx+1) % n] = int.from_bytes(hashlib.sha256((str(signer_idx) + str(message_hash) + 
                                                              str(signer_point.x)).encode()).digest(), byteorder='big') % self.q
        
        # Calculate signer's s value
        s[signer_idx] = (k - private_key * c[signer_idx]) % self.q
        
        return (c[0], s)
    
    def verify_ring_signature(self, message, public_keys, signature):
        """Verify a ring signature without knowing which public key was used."""
        c0, s = signature
        n = len(public_keys)
        
        # Compute message hash
        message_bytes = message.encode() if isinstance(message, str) else message
        message_hash = int.from_bytes(hashlib.sha256(message_bytes).digest(), byteorder='big') % self.q
        
        c = [0] * n
        c[0] = c0
        
        # Verify the ring
        for i in range(n):
            point = s[i] * self.G + c[i] * public_keys[i]
            c[(i+1) % n] = int.from_bytes(hashlib.sha256((str(i) + str(message_hash) + str(point.x)).encode()).digest(), byteorder='big') % self.q
        
        # If the ring closes correctly, the signature is valid
        return c[0] == c0


class StealthAccount:
    def __init__(self, crypto_system, name=None):
        self.crypto_system = crypto_system
        self.name = name if name else f"{DEFAULT_STEALTH_ACCOUNT_NAME_PREFIX}{random.randint(RANDOM_ACCOUNT_ID_MIN, RANDOM_ACCOUNT_ID_MAX)}"
        
        # Generate view keypair (for detecting incoming transactions)
        self.view_sk, self.view_pk = crypto_system.twisted_elgamal_keygen()
        
        # Generate spend keypair (for spending received funds)
        self.spend_sk, self.spend_pk = crypto_system.twisted_elgamal_keygen()
        
        self.balance = 0
        self.received_funds = []  # List of (amount, R, P) tuples
        self.transaction_history = []
    
    def get_public_address(self):
        """Get public address for receiving funds."""
        return (self.view_pk, self.spend_pk)
    
    def receive_funds(self, amount, R, P):
        """Receive funds sent to a stealth address."""
        # Check if this stealth address belongs to us
        if self.crypto_system.recover_stealth_address(R, P, self.view_sk, self.spend_pk):
            self.balance += amount
            self.received_funds.append((amount, R, P))
            self.transaction_history.append(f"Received: +{amount} via stealth address")
            print(f"{self.name}: Received {amount} via stealth address")
            return True
        else:
            print(f"{self.name}: Rejected stealth transaction - not for me")
            return False
    
    def send_funds(self, recipient_address, amount):
        """Send funds to recipient's stealth address."""
        if amount > self.balance:
            print(f"Insufficient funds: {self.balance} < {amount}")
            return False
        
        view_pk, spend_pk = recipient_address
        R, P = self.crypto_system.generate_stealth_address(view_pk, spend_pk)
        
        self.balance -= amount
        self.transaction_history.append(f"Sent: -{amount} to stealth address")
        
        print(f"{self.name}: Sent {amount} to stealth address")
        return (amount, R, P)
    
    def print_status(self):
        """Print account status."""
        print(f"\n--- {self.name} Status ---")
        print(f"Balance: {self.balance}")
        print(f"View Public Key: ({self.view_pk.x}, {self.view_pk.y})")
        print(f"Spend Public Key: ({self.spend_pk.x}, {self.spend_pk.y})")
        print(f"Received Funds: {len(self.received_funds)} transactions")
        print(f"Recent Transactions:")
        for txn in self.transaction_history[-TX_HISTORY_DISPLAY_COUNT:]:
            print(f"  {txn}")
        print()