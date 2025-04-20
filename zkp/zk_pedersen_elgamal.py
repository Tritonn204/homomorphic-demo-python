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

from constants import (
    SMALL_CURVE,
    MAX_VALUE_RANGE,
    TX_MIN_AMOUNT,
    TX_MAX_AMOUNT,
    PEDERSEN_H_GENERATOR_SEED,
    DEFAULT_ZK_ACCOUNT_NAME_PREFIX,
    RANDOM_ACCOUNT_ID_MIN,
    RANDOM_ACCOUNT_ID_MAX,
    TX_HISTORY_DISPLAY_COUNT,
    TX_ID_LENGTH
)

class JsonSerializable:
    def to_dict(self):
        raise NotImplementedError("Must implement to_dict()")

    def to_json(self, **kwargs):
        return json.dumps(self, cls=CustomJSONEncoder, **kwargs)


class ZKProofEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, JsonSerializable):
            return obj.to_dict()
        if isinstance(obj, Point):
            return ZKPoint(obj.curve, obj.x, obj.y).to_dict()
        if isinstance(obj, bytes):
            return obj.to_hex()
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
    def __init__(self, curve_name=SMALL_CURVE):
        # Cryptographic Primitives - same as before
        self.curve = registry.get_curve(curve_name)
        self.G = self.curve.g
        self.q = self.curve.field.n
        
        # Create second generator for Pedersen commitments
        h_seed = hashlib.sha256(PEDERSEN_H_GENERATOR_SEED).digest()
        h_value = int.from_bytes(h_seed, byteorder="big") % self.q
        self.H = h_value * self.G
        
        self.MAX_VALUE_RANGE = MAX_VALUE_RANGE
        self.VALUE_POINTS = {}
    
    # Keep the original methods for compatibility
    def generate_value_table(self, max_range=None):
        """Generate precomputed table of values with progress reporting"""
        if max_range is None:
            max_range = self.MAX_VALUE_RANGE
            
        print(f"Generating precomputed value table (0-{max_range})...")
        
        for i in tqdm(range(max_range), desc="Building value table"):
            point = i * self.G
            self.VALUE_POINTS[point.x] = i
        
        print(f"✓ Precomputed {max_range} values for constant-time lookup")
        return self.VALUE_POINTS
    
    def constant_time_decrypt(self, ciphertext, sk, max_range=None):
        """Decrypt ElGamal ciphertext in constant time"""
        if max_range is None:
            max_range = self.MAX_VALUE_RANGE
            
        c1, c2 = ciphertext
        decrypted_point = c2 - sk * c1
        
        return self.VALUE_POINTS.get(decrypted_point.x)
    
    def pedersen_commit(self, value, blinding_factor):
        """Create a Pedersen commitment to a value"""
        result = value * self.G + blinding_factor * self.H
        # Return as ZKPoint if needed for serialization
        return ZKPoint(result.curve, result.x, result.y)
    
    def hash_to_scalar(self, data):
        """Hash data to a scalar value in the range [1, q-1]"""
        if isinstance(data, (list, tuple)):
            # Handle multiple arguments by joining them
            data = ''.join([f"{arg}" for arg in data])
        
        data_bytes = data.encode() if isinstance(data, str) else data
        return int.from_bytes(hashlib.sha256(data_bytes).digest(), byteorder="big") % self.q
        
    def create_bit_proof(self, bit_comm, bit, r_bit):
        """Create an OR proof that bit_comm commits to either 0 or 1."""
        if bit == 0:
            # Real proof for 0: bit_comm = 0*G + r_bit*H = r_bit*H
            # We need to prove knowledge of r_bit such that bit_comm = r_bit*H
            
            # Real branch (proving commitment = 0)
            w0 = random.randint(1, self.q-1)
            t0 = w0 * self.H  # t0 is commitment for the real proof
            
            # Simulated branch (proving commitment = 1)
            c1 = random.randint(1, self.q-1)  
            s1 = random.randint(1, self.q-1)
            t1 = s1 * self.H - c1 * (bit_comm - self.G)  # Simulated proof for bit = 1
            
            # Compute challenge
            c = self.hash_to_scalar(f"{bit_comm.x}:{bit_comm.y}:{t0.x}:{t0.y}:{t1.x}:{t1.y}")
            
            # Complete real proof
            c0 = (c - c1) % self.q
            s0 = (w0 + c0 * r_bit) % self.q
            
        else:  # bit == 1
            # Real proof for 1: bit_comm = 1*G + r_bit*H
            # We need to prove knowledge of r_bit such that bit_comm - G = r_bit*H
            
            # Real branch (proving commitment = 1)
            w1 = random.randint(1, self.q-1)
            t1 = w1 * self.H  # t1 is commitment for the real proof
            
            # Simulated branch (proving commitment = 0)
            c0 = random.randint(1, self.q-1)
            s0 = random.randint(1, self.q-1)
            t0 = s0 * self.H - c0 * bit_comm  # Simulated proof for bit = 0
            
            # Compute challenge
            c = self.hash_to_scalar(f"{bit_comm.x}:{bit_comm.y}:{t0.x}:{t0.y}:{t1.x}:{t1.y}")
            
            # Complete real proof
            c1 = (c - c0) % self.q
            s1 = (w1 + c1 * r_bit) % self.q
        
        return {
            't0': t0,
            't1': t1,
            'c': c,
            'c0': c0,
            'c1': c1,
            's0': s0,
            's1': s1
        }

    def verify_bit_proof(self, bit_comm, proof_data):
        """Verify an OR proof that bit_comm commits to either 0 or 1."""
        t0 = proof_data['t0']
        t1 = proof_data['t1']
        c = proof_data['c']
        c0 = proof_data['c0']
        c1 = proof_data['c1']
        s0 = proof_data['s0']
        s1 = proof_data['s1']
        
        # Check that sub-challenges sum to the overall challenge
        if (c0 + c1) % self.q != c:
            print(f"Challenge sum failed")
            return False
        
        # Recompute the challenge
        c_computed = self.hash_to_scalar(f"{bit_comm.x}:{bit_comm.y}:{t0.x}:{t0.y}:{t1.x}:{t1.y}")
        if c_computed != c:
            print(f"Challenge recomputation failed")
            return False
        
        # Verify both branches
        # For case 0 (commitment = 0): verify t0 = s0*H - c0*bit_comm
        t0_check = s0 * self.H - c0 * bit_comm
        
        # For case 1 (commitment = 1): verify t1 = s1*H - c1*(bit_comm - G)
        t1_check = s1 * self.H - c1 * (bit_comm - self.G)
        
        if t0_check != t0:
            print(f"t0 verification failed")
            return False
        
        if t1_check != t1:
            print(f"t1 verification failed")
            return False
        
        return True

    def range_proof(self, v, min_val=TX_MIN_AMOUNT, max_val=TX_MAX_AMOUNT):
        """Generate a zero-knowledge range proof for v in [min_val, max_val]."""
        if not (min_val <= v <= max_val):
            raise ValueError(f"Value {v} is not in range [{min_val}, {max_val}]")
        
        # Shift the value to range [0, max_val - min_val]
        shifted_value = v - min_val
        range_size = max_val - min_val
        
        # Generate Pedersen commitment to the actual value v
        blinding = random.randint(1, self.q-1)
        commitment = self.pedersen_commit(v, blinding)
        
        # Binary decomposition of shifted_value
        n_bits = range_size.bit_length()
        bits = []
        bit_blindings = []
        
        # Extract each bit and generate a random blinding factor
        value_copy = shifted_value
        for i in range(n_bits):
            bits.append(value_copy & 1)
            bit_blindings.append(random.randint(1, self.q-1))
            value_copy >>= 1
        
        # Create commitments to each bit
        bit_commitments = []
        for bit, r_bit in zip(bits, bit_blindings):
            bit_commitment = self.pedersen_commit(bit, r_bit)
            bit_commitments.append(bit_commitment)
        
        # Create proofs that each commitment is to either 0 or 1
        bit_proofs = []
        for i, (bit, r_bit) in enumerate(zip(bits, bit_blindings)):
            bit_comm = bit_commitments[i]
            bit_proof = self.create_bit_proof(bit_comm, bit, r_bit)
            bit_proofs.append(bit_proof)
        
        # Create proof that the weighted sum of bit commitments equals the shifted commitment
        weighted_blinding = 0
        for i, r_bit in enumerate(bit_blindings):
            weighted_blinding = (weighted_blinding + (2**i) * r_bit) % self.q
        
        blinding_diff = (blinding - weighted_blinding) % self.q
        
        w_sum = random.randint(1, self.q-1)
        t_sum = w_sum * self.H
        c_sum = self.hash_to_scalar(f"{commitment.x}:{commitment.y}:{t_sum.x}:{t_sum.y}")
        s_sum = (w_sum + c_sum * blinding_diff) % self.q
        
        return {
            'commitment': commitment,
            'range': (min_val, max_val),
            'bit_commitments': bit_commitments,
            'bit_proofs': bit_proofs,
            'sum_proof': {
                't': t_sum,
                'c': c_sum,
                's': s_sum
            }
        }

    def verify_range_proof(self, proof):
        """Verify a zero-knowledge range proof."""
        commitment = proof['commitment']
        min_val, max_val = proof['range']
        bit_commitments = proof['bit_commitments']
        bit_proofs = proof['bit_proofs']
        sum_proof = proof['sum_proof']
        
        n_bits = (max_val - min_val).bit_length()
        
        if len(bit_commitments) != n_bits or len(bit_proofs) != n_bits:
            return False
        
        # Verify each bit proof (that each commitment is to either 0 or 1)
        for i, (bit_comm, proof_data) in enumerate(zip(bit_commitments, bit_proofs)):
            t0 = proof_data['t0']
            t1 = proof_data['t1']
            c = proof_data['c']
            c0 = proof_data['c0']
            c1 = proof_data['c1']
            s0 = proof_data['s0']
            s1 = proof_data['s1']
            
            # Check that the sub-challenges sum to the overall challenge
            if (c0 + c1) % self.q != c:
                return False
            
            # Recompute the challenge using the same hash as in creation
            c_computed = self.hash_to_scalar(f"{bit_comm.x}:{bit_comm.y}:{t0.x}:{t0.y}:{t1.x}:{t1.y}")
            if c_computed != c:
                return False
            
            # Verify both branches of the OR proof
            # For case 0 (proving commitment is to 0):
            # t0 = s0 * H - c0 * bit_comm
            t0_check = s0 * self.H - c0 * bit_comm
            
            # For case 1 (proving commitment is to 1):
            # t1 = s1 * H - c1 * (bit_comm - G)
            t1_check = s1 * self.H + c1 * self.G - c1 * bit_comm
            
            if t0_check != t0 or t1_check != t1:
                return False
        
        # Verify the weighted sum proof
        weighted_commitment = 0 * self.G
        
        for i, bit_comm in enumerate(bit_commitments):
            weight = 2**i
            weighted_commitment += weight * bit_comm
        
        expected_commitment = weighted_commitment + (min_val * self.G)
        diff_commitment = commitment - expected_commitment
        
        t_sum = sum_proof['t']
        c_sum = sum_proof['c']
        s_sum = sum_proof['s']
        
        c_sum_computed = self.hash_to_scalar(f"{commitment.x}:{commitment.y}:{t_sum.x}:{t_sum.y}")
        if c_sum_computed != c_sum:
            return False
        
        # Verify the Schnorr-style proof for the blinding factor difference
        t_sum_check = s_sum * self.H - c_sum * diff_commitment
        if t_sum_check != t_sum:
            return False
        
        return True

    def schnorr_prove(self, x, P=None):
        """Generate a Schnorr proof of knowledge of discrete logarithm."""
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
        """Verify a Schnorr proof of knowledge."""
        c, s = proof
        
        # Reconstruct R = s*G + c*P
        R = s * self.G + c * P
        
        # Check if challenge matches
        expected_c = self.hash_to_scalar(f"{P.x}:{P.y}:{R.x}:{R.y}")
        
        return c == expected_c
    
    
    def create_zk_transaction(self, sender_sk, sender_pk, recipient_pk, amount, sender_balance=None):
        """Create a transaction with aggregated range proofs."""
        # Generate randomness for transaction
        tx_randomness = random.randint(1, self.q-1)
        
        # Encrypt the amount for recipient
        recipient_ciphertext = (tx_randomness * self.G, amount * self.G + tx_randomness * recipient_pk)
        
        # Generate aggregated range proof for amount
        amount_proof = self.range_proof(amount, TX_MIN_AMOUNT, TX_MAX_AMOUNT)
        
        # Generate balance proof if needed
        balance_proof = None
        if sender_balance is not None:
            if sender_balance < amount:
                raise ValueError("Insufficient balance for transaction")
                
            balance_proof = self.range_proof(
                sender_balance - amount, 
                TX_MIN_AMOUNT, 
                TX_MAX_AMOUNT
            )
        
        # Create signature
        message = f"{sender_pk.x}:{sender_pk.y}:{recipient_pk.x}:{recipient_pk.y}:{recipient_ciphertext[0].x}"
        signature = self.schnorr_prove(sender_sk)
        
        # Transaction with aggregated proofs
        transaction = {
            'sender_pk': sender_pk,
            'recipient_pk': recipient_pk,
            'ciphertext': recipient_ciphertext,
            'amount_proof': amount_proof,
            'balance_proof': balance_proof,
            'signature': signature
        }
        
        return transaction


    def _is_on_curve(self, point):
        """Verify that a point lies on the elliptic curve."""
        # Check if the point satisfies the curve equation
        # For secp192r1: y^2 = x^3 + a*x + b (mod p)
        a = self.curve.a
        b = self.curve.b
        p = self.curve.field.p
        
        left = (point.y * point.y) % p
        right = (point.x * point.x * point.x + a * point.x + b) % p
        
        return left == right
        
    def verify_zk_transaction(self, transaction):
        """Verify a ZK transaction without learning the amount."""
        sender_address = transaction['sender_address']
        signature = transaction['signature']
        amount_proof = transaction['amount_proof']
        balance_proof = transaction['balance_proof']
        
        # Reconstruct sender public key from address
        try:
            x_str, y_str = sender_address.split(':')
            sender_x = int(x_str)
            sender_y = int(y_str)
            sender_pk = ZKPoint(self.curve, sender_x, sender_y)
            
            if not self._is_on_curve(sender_pk):
                print("❌ Invalid sender address (not on curve)")
                return False
                
        except (ValueError, AttributeError) as e:
            print(f"❌ Invalid sender address format: {e}")
            return False
        
        # Step 1: Verify sender's signature
        if not self.schnorr_verify(sender_pk, signature):
            print("❌ Invalid signature")
            return False
        
        # Step 2: Verify that amount is positive (range proof)
        # Pass ciphertext components to the verification function
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
        self.name = name if name else f"{DEFAULT_ZK_ACCOUNT_NAME_PREFIX}{random.randint(RANDOM_ACCOUNT_ID_MIN, RANDOM_ACCOUNT_ID_MAX)}"
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
            'tx_id': hashlib.sha256(f"{time.time()}:{self.pk.x}:{recipient.pk.x}:{amount}".encode()).hexdigest()[:TX_ID_LENGTH]
        })
        
        return True
    
    def print_status(self):
        """Display account status."""
        print(f"\n--- {self.name} Status ---")
        print(f"Balance: {self.balance}")
        print(f"Public Key: ({self.pk.x % 10000}..., {self.pk.y % 10000}...)")
        
        if self.transactions:
            print(f"\nRecent Transactions:")
            for tx in self.transactions[-TX_HISTORY_DISPLAY_COUNT:]:
                if tx['type'] == 'deposit':
                    print(f"  Deposit: +{tx['amount']}")
                elif tx['type'] == 'send':
                    print(f"  Sent: -{tx['amount']} to {tx['recipient']} (ID: {tx.get('tx_id', 'N/A')})")
                elif tx['type'] == 'receive':
                    print(f"  Received: +{tx['amount']} from {tx.get('sender', 'Unknown')} (ID: {tx.get('tx_id', 'N/A')})")
        
        print()