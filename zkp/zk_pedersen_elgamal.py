import hashlib
import random
import time
import threading
import multiprocessing
import json
from tqdm import tqdm
from .base import TransactionProof, RangeProof
from tinyec import registry
from tinyec.ec import Point

class JsonSerializable:
    def to_dict(self):
        raise NotImplementedError("Must implement to_dict()")

    def to_json(self, **kwargs):
        return json.dumps(self, cls=CustomJSONEncoder, **kwargs)


class ZKPointEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, JsonSerializable):
            return obj.to_dict()
        return super().default(obj)

class ZKPoint(Point, JsonSerializable):
    def __init__(self, curve, x, y):
        super().__init__(curve, x, y)

    def to_dict(self):
        return {
            "x": self.x,
            "y": self.y,
            "curve": self.curve.name
        }

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_dict(cls, data):
        curve = registry.get_curve(data["curve"])
        return cls(curve, data["x"], data["y"])

    @classmethod
    def from_json(cls, json_str):
        return cls.from_dict(json.loads(json_str))

class ZKPedersenElGamal:
    def __init__(self, curve_name='secp192r1'):
        # Cryptographic Primitives
        self.curve = registry.get_curve(curve_name)  # Speed is more important for demo
        self.G = self.curve.g
        self.q = self.curve.field.n
        
        # Create second generator for Pedersen commitments
        h_seed = hashlib.sha256(b"PEDERSEN_H_GENERATOR").digest()
        h_value = int.from_bytes(h_seed, byteorder="big") % self.q
        self.H = h_value * self.G
        
        self.MAX_VALUE_RANGE = 10000
        self.VALUE_POINTS = {}
    
    def generate_value_table(self, max_range=None):
        """Generate precomputed table of values with progress reporting"""
        if max_range is None:
            max_range = self.MAX_VALUE_RANGE
            
        print(f"Generating precomputed value table (0-{max_range})...")
        
        # Create progress bar
        for i in tqdm(range(max_range), desc="Building value table"):
            point = i * self.G
            self.VALUE_POINTS[point.x] = i
        
        print(f"✓ Precomputed {max_range} values for constant-time lookup")
        return self.VALUE_POINTS
    
    def constant_time_decrypt(self, ciphertext, sk, max_range=None):
        """Decrypt ElGamal ciphertext in constant time"""
        if max_range is None:
            max_range = self.MAX_VALUE_RANGE
            
        # Decrypt the point
        c1, c2 = ciphertext
        decrypted_point = c2 - sk * c1
        
        # Fast lookup from precomputed table (no need for scanning!)
        return self.VALUE_POINTS.get(decrypted_point.x)
    
    def pedersen_commit(self, value, blinding_factor):
        """Create a Pedersen commitment to a value"""
        result = value * self.G + blinding_factor * self.H
        return ZKPoint(result.curve, result.x, result.y)
    
    def hash_to_scalar(self, data):
        """Hash data to a scalar value in the range [1, q-1]"""
        data_bytes = data.encode() if isinstance(data, str) else data
        return int.from_bytes(hashlib.sha256(data_bytes).digest(), byteorder="big") % self.q
    
    def schnorr_prove(self, x, P=None):
        """Generate a Schnorr proof of knowledge of discrete logarithm.
        
        Args:
            x: Secret value (discrete logarithm)
            P: Public point (default: x*G)
        
        Returns:
            (c, s): A Schnorr proof
        """
        if P is None:
            P = x * self.G
            
        # Random nonce
        k = random.randint(1, self.q-1)
        R = k * self.G
        
        # Challenge
        c = self.hash_to_scalar(f"{P.x}:{P.y}:{R.x}:{R.y}")
        
        # Response
        s = (k - c * x) % self.q
        
        return (c, s)
    
    def schnorr_verify(self, P, proof):
        """Verify a Schnorr proof of knowledge.
        
        Args:
            P: Public point claimed to be known
            proof: (c, s) Schnorr proof
            
        Returns:
            bool: True if proof is valid
        """
        c, s = proof
        
        # Reconstruct R = s*G + c*P
        R = s * self.G + c * P
        
        # Check if challenge matches
        expected_c = self.hash_to_scalar(f"{P.x}:{P.y}:{R.x}:{R.y}")
        
        return c == expected_c
    
    def range_proof(self, v, min_val=0, max_val=100):
        """Generate a zero-knowledge range proof for v in [min_val, max_val].
        
        This is a simulated efficient range proof (not a full Bulletproof implementation).
        """
        if not (min_val <= v <= max_val):
            raise ValueError(f"Value {v} is not in range [{min_val}, {max_val}]")
            
        # In a real system, we would produce a Bulletproof here
        # For this demo, we'll simulate it with a Pedersen commitment and Schnorr proof
        
        # Commit to the value 
        r = random.randint(1, self.q-1)
        C = self.pedersen_commit(v, r)
        
        # Generate a simulated range proof (in reality this would be much more complex)
        simulated_proof = {
            'commitment': C,
            'range': (min_val, max_val),
            'proof_data': self.hash_to_scalar(f"range:{v}:{r}:{min_val}:{max_val}"),
            'v': v,  # Real proof wouldn't include this!
            'r': r   # Real proof wouldn't include this!
        }
        
        return simulated_proof
    
    def verify_range_proof(self, proof):
        """Verify a range proof (simulated version)."""
        C = proof['commitment']
        min_val, max_val = proof['range']
        
        # In a real ZKP system, we would verify the mathematical proof
        # For our demo, we reconstruct the commitment and check if hashes match
        
        # THIS IS INSECURE - only for demonstration - a real system wouldn't know v and r
        v, r = proof['v'], proof['r']
        expected_C = self.pedersen_commit(v, r)
        
        if expected_C.x != C.x or expected_C.y != C.y:
            return False
        
        # Check if value is in range (normally this would be cryptographic)
        if not (min_val <= v <= max_val):
            return False
        
        expected_proof_data = self.hash_to_scalar(f"range:{v}:{r}:{min_val}:{max_val}")
        return proof['proof_data'] == expected_proof_data
    
    def create_zk_transaction(self, sender_sk, sender_pk, recipient_pk, amount, sender_balance=None):
        """Create an encrypted transaction with ZK proofs."""
        # Step 1: Generate randomness for this transaction
        tx_randomness = random.randint(1, self.q-1)
        
        # Step 2: Encrypt the amount for recipient with ElGamal
        recipient_ciphertext = (tx_randomness * self.G, amount * self.G + tx_randomness * recipient_pk)
        
        # Step 3: Create a range proof to prove amount is positive without revealing it
        amount_range_proof = self.range_proof(amount, 0, 10000)
        
        # Step 4: If we know sender's balance, create proof that balance >= amount
        balance_sufficient_proof = None
        if sender_balance is not None:
            if sender_balance < amount:
                raise ValueError("Insufficient balance for transaction")
            
            # Create proof that balance - amount >= 0
            # In reality this would be a proper ZK proof, here we simulate
            balance_sufficient_proof = self.range_proof(sender_balance - amount, 0, 10000)
        
        # Step 5: Sign the transaction
        message = f"{recipient_pk.x}:{recipient_pk.y}:{amount}:{tx_randomness}"
        signature = self.schnorr_prove(sender_sk)
        
        # Construct transaction object
        transaction = {
            'sender_pk': sender_pk,
            'recipient_pk': recipient_pk,
            'ciphertext': recipient_ciphertext,
            'amount_proof': amount_range_proof,
            'balance_proof': balance_sufficient_proof,
            'signature': signature,
            'tx_randomness': tx_randomness,  # In practice, this would be hidden
            'amount': amount                 # In practice, this would be hidden
        }
        
        return transaction
    
    def verify_zk_transaction(self, transaction):
        """Verify a ZK transaction without learning the amount."""
        # Extract transaction parts
        sender_pk = transaction['sender_pk']
        signature = transaction['signature']
        amount_proof = transaction['amount_proof']
        balance_proof = transaction['balance_proof']
        
        # Step 1: Verify sender's signature
        if not self.schnorr_verify(sender_pk, signature):
            print("❌ Invalid signature")
            return False
        
        # Step 2: Verify that amount is positive (range proof)
        if not self.verify_range_proof(amount_proof):
            print("❌ Invalid amount range proof")
            return False
        
        # Step 3: If balance proof provided, verify sender has sufficient funds
        if balance_proof and not self.verify_range_proof(balance_proof):
            print("❌ Invalid balance proof")
            return False
        
        print("✓ Transaction verified successfully!")
        return True


class ZKAccount:
    """Account with private transaction support using ZK proofs."""
    def __init__(self, zk_system, name=None):
        self.zk_system = zk_system
        self.name = name if name else f"ZKAccount-{random.randint(1000, 9999)}"
        self.sk, self.pk = self._generate_keypair()
        self.balance = 0
        self.transactions = []
    
    def _generate_keypair(self):
        sk = random.randint(1, self.zk_system.q-1)
        pk = sk * self.zk_system.G
        return sk, pk
    
    def deposit(self, amount):
        """Deposit funds into account."""
        self.balance += amount
        self.transactions.append({
            'type': 'deposit',
            'amount': amount,
            'timestamp': time.time()
        })
        print(f"{self.name} deposited {amount}")
    
    def send(self, recipient, amount):
        """Send funds to recipient with privacy."""
        if amount > self.balance:
            print(f"❌ Insufficient balance: {self.balance} < {amount}")
            return False
        
        # Create ZK transaction
        tx = self.zk_system.create_zk_transaction(
            self.sk, self.pk, recipient.pk, amount, self.balance
        )
        
        # Update local state
        self.balance -= amount
        self.transactions.append({
            'type': 'send',
            'recipient': recipient.name,
            'amount': amount,
            'timestamp': time.time(),
            'tx_id': hashlib.sha256(f"{time.time()}:{self.pk.x}:{recipient.pk.x}:{amount}".encode()).hexdigest()[:8]
        })
        
        # Tell recipient to receive
        recipient.receive(tx)
        return True
    
    def receive(self, tx):
        """Receive funds via private transaction."""
        # In reality, we would scan the blockchain for transactions to our address
        # For this demo, we simulate direct delivery
        
        # Verify the transaction
        if not self.zk_system.verify_zk_transaction(tx):
            print(f"❌ {self.name} rejected invalid transaction")
            return False
        
        # Decrypt the amount
        c1, c2 = tx['ciphertext']
        amount = tx['amount']  # In reality, we would decrypt this with our private key
        
        # Update local state
        self.balance += amount
        self.transactions.append({
            'type': 'receive',
            'sender': f"Account-{tx['sender_pk'].x % 10000}",
            'amount': amount,
            'timestamp': time.time(),
            'tx_id': hashlib.sha256(f"{time.time()}:{tx['sender_pk'].x}:{self.pk.x}:{amount}".encode()).hexdigest()[:8]
        })
        
        print(f"{self.name} received {amount}")
        return True
    
    def print_status(self):
        """Display account status."""
        print(f"\n--- {self.name} Status ---")
        print(f"Balance: {self.balance}")
        print(f"Public Key: ({self.pk.x % 10000}..., {self.pk.y % 10000}...)")
        
        if self.transactions:
            print(f"\nRecent Transactions:")
            for tx in self.transactions[-3:]:
                if tx['type'] == 'deposit':
                    print(f"  Deposit: +{tx['amount']}")
                elif tx['type'] == 'send':
                    print(f"  Sent: -{tx['amount']} to {tx['recipient']} (ID: {tx.get('tx_id', 'N/A')})")
                elif tx['type'] == 'receive':
                    print(f"  Received: +{tx['amount']} from {tx.get('sender', 'Unknown')} (ID: {tx.get('tx_id', 'N/A')})")
        
        print()
