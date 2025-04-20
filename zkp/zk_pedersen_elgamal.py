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

    def range_proof(self, v, min_val=TX_MIN_AMOUNT, max_val=TX_MAX_AMOUNT, commitment=None, blinding_factor=None):
        """Generate a zero-knowledge range proof for v in [min_val, max_val]."""
        if not (min_val <= v <= max_val):
            raise ValueError(f"Value {v} is not in range [{min_val}, {max_val}]")
        
        # Shift the value to range [0, max_val - min_val]
        shifted_value = v - min_val
        range_size = max_val - min_val
        
        # Generate Pedersen commitment to the actual value v
        blinding = random.randint(1, self.q-1)

        if commitment is None:
            if blinding_factor is not None:
                raise ValueError("Cannot provide blinding_factor without commitment")
            blinding = random.randint(1, self.q-1)
            commitment = self.pedersen_commit(v, blinding)
        else:
            if blinding_factor is None:
                raise ValueError("Must provide blinding_factor with commitment")
            # Verify the commitment is correct
            expected_commitment = self.pedersen_commit(v, blinding_factor)
            if commitment != expected_commitment:
                raise ValueError("Provided commitment doesn't match value and blinding factor")
            blinding = blinding_factor
        
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

    def schnorr_sign(self, sk, message):
        """Create a Schnorr signature for a message using private key sk."""
        # Generate random nonce
        k = random.randint(1, self.q-1)
        R = k * self.G
        
        # Generate public key from private key
        pk = sk * self.G
        
        # Hash the message together with public key and R
        # This binds the signature to the message
        e = self.hash_to_scalar(f"{pk.x}:{pk.y}:{R.x}:{R.y}:{message}")
        
        # Calculate signature
        s = (k - e * sk) % self.q
        
        return {'R': R, 'e': e, 's': s}

    def schnorr_verify_message(self, pk, signature, message):
        """Verify a Schnorr signature."""
        R = signature['R']
        e = signature['e']
        s = signature['s']
        
        # Recompute the challenge
        computed_e = self.hash_to_scalar(f"{pk.x}:{pk.y}:{R.x}:{R.y}:{message}")
        
        if computed_e != e:
            return False
        
        # Verify the signature equation: R = s*G + e*pk
        R_check = s * self.G + e * pk
        
        return R_check == R

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
    
    def create_subtraction_proof(self, original_ciphertext, amount_ciphertext, result_ciphertext):
        """Prove that result_ciphertext encrypts (original - amount) without revealing values."""
        # For ElGamal, we can use the homomorphic property:
        # Enc(a - b) = Enc(a) / Enc(b)
        
        # First, verify the relationship holds
        expected_c1 = original_ciphertext[0] - amount_ciphertext[0]
        expected_c2 = original_ciphertext[1] - amount_ciphertext[1]
        
        if result_ciphertext[0] != expected_c1 or result_ciphertext[1] != expected_c2:
            raise ValueError("Ciphertext relationship doesn't hold")
        
        # Create a proof that this relationship is correct
        # This can be a simple signature or hash proof since the relationship is publicly verifiable
        proof_data = {
            'original_c1': original_ciphertext[0],
            'original_c2': original_ciphertext[1],
            'amount_c1': amount_ciphertext[0],
            'amount_c2': amount_ciphertext[1],
            'result_c1': result_ciphertext[0],
            'result_c2': result_ciphertext[1],
        }
        
        # Create a commitment to the proof
        proof_hash = self.hash_to_scalar(
            f"{original_ciphertext[0].x}:{original_ciphertext[0].y}:"
            f"{original_ciphertext[1].x}:{original_ciphertext[1].y}:"
            f"{amount_ciphertext[0].x}:{amount_ciphertext[0].y}:"
            f"{amount_ciphertext[1].x}:{amount_ciphertext[1].y}:"
            f"{result_ciphertext[0].x}:{result_ciphertext[0].y}:"
            f"{result_ciphertext[1].x}:{result_ciphertext[1].y}"
        )
        
        proof_data['hash'] = proof_hash
        return proof_data

    def verify_subtraction_proof(self, proof_data):
        """Verify that result_ciphertext encrypts (original - amount)."""
        # Extract all components
        original_c1 = proof_data['original_c1']
        original_c2 = proof_data['original_c2']
        amount_c1 = proof_data['amount_c1']
        amount_c2 = proof_data['amount_c2']
        result_c1 = proof_data['result_c1']
        result_c2 = proof_data['result_c2']
        
        # Check the homomorphic relationship
        if result_c1 != (original_c1 - amount_c1):
            return False
        
        if result_c2 != (original_c2 - amount_c2):
            return False
        
        # Verify the hash
        expected_hash = self.hash_to_scalar(
            f"{original_c1.x}:{original_c1.y}:"
            f"{original_c2.x}:{original_c2.y}:"
            f"{amount_c1.x}:{amount_c1.y}:"
            f"{amount_c2.x}:{amount_c2.y}:"
            f"{result_c1.x}:{result_c1.y}:"
            f"{result_c2.x}:{result_c2.y}"
        )
        
        return expected_hash == proof_data['hash']

    def create_commitment_equality_proof(self, v, elgamal_randomness, pedersen_blinding, ciphertext, 
                                      commitment, recipient_pk):
        """Prove that an ElGamal ciphertext and a Pedersen commitment hide the same value."""
        # The ElGamal ciphertext is (c1, c2) where:
        #   c1 = elgamal_randomness * G
        #   c2 = v * G + elgamal_randomness * recipient_pk
        # 
        # The Pedersen commitment is:
        #   comm = v * G + pedersen_blinding * H
        #
        # We need to prove these contain the same v without revealing v
        
        # Generate random values for the proof
        rv = random.randint(1, self.q-1)  # For value
        re = random.randint(1, self.q-1)  # For ElGamal randomness
        rp = random.randint(1, self.q-1)  # For Pedersen blinding
        
        # Compute commitments for the proof
        # For the ElGamal part
        R1 = re * self.G
        R2 = rv * self.G + re * recipient_pk
        
        # For the Pedersen part
        R3 = rv * self.G + rp * self.H
        
        # Create challenge
        c = self.hash_to_scalar(f"{ciphertext[0].x}:{ciphertext[0].y}:{ciphertext[1].x}:{ciphertext[1].y}:"
                              f"{commitment.x}:{commitment.y}:{R1.x}:{R1.y}:{R2.x}:{R2.y}:{R3.x}:{R3.y}")
        
        # Create responses
        sv = (rv + c * v) % self.q
        se = (re + c * elgamal_randomness) % self.q
        sp = (rp + c * pedersen_blinding) % self.q
        
        return {
            'R1': R1,
            'R2': R2,
            'R3': R3,
            'c': c,
            'sv': sv,
            'se': se,
            'sp': sp
        }

    def verify_commitment_equality_proof(self, ciphertext, commitment, recipient_pk, proof):
        """Verify that an ElGamal ciphertext and a Pedersen commitment hide the same value."""
        R1 = proof['R1']
        R2 = proof['R2']
        R3 = proof['R3']
        c = proof['c']
        sv = proof['sv']
        se = proof['se']
        sp = proof['sp']
        
        # Recompute challenge
        c_expected = self.hash_to_scalar(f"{ciphertext[0].x}:{ciphertext[0].y}:{ciphertext[1].x}:{ciphertext[1].y}:"
                                        f"{commitment.x}:{commitment.y}:{R1.x}:{R1.y}:{R2.x}:{R2.y}:{R3.x}:{R3.y}")
        
        if c != c_expected:
            return False
        
        # Verify the proof equations
        # Check ElGamal part
        R1_check = se * self.G - c * ciphertext[0]
        R2_check = sv * self.G + se * recipient_pk - c * ciphertext[1]
        
        if R1_check != R1 or R2_check != R2:
            return False
        
        # Check Pedersen part
        R3_check = sv * self.G + sp * self.H - c * commitment
        
        if R3_check != R3:
            return False
        
        return True

    def create_transaction_signature(self, sender_sk, recipient_pk, ciphertext, 
                                  amount_proof, balance_proof):
        """Create a signature over all important transaction components."""
        # Create a message that includes all critical components
        c1, c2 = ciphertext
        message_components = [
            f"recipient:{recipient_pk.x}:{recipient_pk.y}",
            f"ciphertext_c1:{c1.x}:{c1.y}",
            f"ciphertext_c2:{c2.x}:{c2.y}",
            f"amount_proof_commitment:{amount_proof['range_proof']['commitment'].x}:{amount_proof['range_proof']['commitment'].y}",
            f"amount_equality_proof:{amount_proof['equality_proof']['c']}",  # Include key parts of equality proof
        ]
        
        # If there's a balance proof, include it
        if balance_proof:
            message_components.append(f"balance_remaining_c1:{balance_proof['remaining_balance_ciphertext'][0].x}:{balance_proof['remaining_balance_ciphertext'][0].y}")
            message_components.append(f"balance_remaining_c2:{balance_proof['remaining_balance_ciphertext'][1].x}:{balance_proof['remaining_balance_ciphertext'][1].y}")
            message_components.append(f"balance_proof_commitment:{balance_proof['range_proof']['commitment'].x}:{balance_proof['range_proof']['commitment'].y}")
            message_components.append(f"balance_equality_proof:{balance_proof['equality_proof']['c']}")
            message_components.append(f"balance_subtraction_hash:{balance_proof['subtraction_proof']['hash']}")
        
        # Concatenate all components
        message = ":".join(message_components)
        
        # Sign the message
        return self.schnorr_sign(sender_sk, message)

    def create_zk_transaction(self, sender_sk, sender_pk, recipient_pk, amount, 
                            sender_balance=None, balance_ciphertext=None):
        """Create a transaction with properly linked range proofs for both amount and balance."""
        # Generate randomness for ElGamal encryption of amount
        amount_elgamal_randomness = random.randint(1, self.q-1)
        
        # Encrypt the amount for recipient using standard ElGamal
        recipient_ciphertext = (
            amount_elgamal_randomness * self.G, 
            amount * self.G + amount_elgamal_randomness * recipient_pk
        )
        
        # Generate a Pedersen commitment to the amount
        amount_pedersen_blinding = random.randint(1, self.q-1)
        amount_commitment = self.pedersen_commit(amount, amount_pedersen_blinding)
        
        # Create proof that the ciphertext and commitment contain the same amount
        amount_equality_proof = self.create_commitment_equality_proof(
            amount, 
            amount_elgamal_randomness, 
            amount_pedersen_blinding, 
            recipient_ciphertext, 
            amount_commitment, 
            recipient_pk
        )
        
        # Generate range proof for the amount
        amount_range_proof = self.range_proof(
            amount,
            TX_MIN_AMOUNT,
            TX_MAX_AMOUNT,
            commitment=amount_commitment,
            blinding_factor=amount_pedersen_blinding
        )
        
        # Generate balance proof if needed
        balance_proof = None
        balance_equality_proof = None
        
        if sender_balance is not None and balance_ciphertext is not None:
            if sender_balance < amount:
                raise ValueError("Insufficient balance for transaction")
            
            remaining_balance = sender_balance - amount
            
            # Create new ciphertext for remaining balance
            balance_elgamal_randomness = random.randint(1, self.q-1)
            remaining_balance_ciphertext = (
                balance_elgamal_randomness * self.G,
                remaining_balance * self.G + balance_elgamal_randomness * sender_pk
            )
            
            # Generate a Pedersen commitment to the remaining balance
            balance_pedersen_blinding = random.randint(1, self.q-1)
            balance_commitment = self.pedersen_commit(remaining_balance, balance_pedersen_blinding)
            
            # Create proof that the remaining balance ciphertext and commitment contain the same value
            balance_equality_proof = self.create_commitment_equality_proof(
                remaining_balance,
                balance_elgamal_randomness,
                balance_pedersen_blinding,
                remaining_balance_ciphertext,
                balance_commitment,
                sender_pk
            )
            
            # Generate range proof for the remaining balance
            balance_range_proof = self.range_proof(
                remaining_balance,
                TX_MIN_AMOUNT,
                TX_MAX_AMOUNT,
                commitment=balance_commitment,
                blinding_factor=balance_pedersen_blinding
            )
            
            # Create proof that remaining balance = original balance - amount
            # This is done using homomorphic properties of ElGamal and Pedersen commitments
            balance_subtraction_proof = self.create_subtraction_proof(
                balance_ciphertext,    # Original balance ciphertext
                recipient_ciphertext,  # Amount ciphertext
                remaining_balance_ciphertext  # Result ciphertext
            )
            
            balance_proof = {
                'remaining_balance_ciphertext': remaining_balance_ciphertext,
                'range_proof': balance_range_proof,
                'equality_proof': balance_equality_proof,
                'subtraction_proof': balance_subtraction_proof
            }
        
        # Create signature that covers everything
        signature = self.create_transaction_signature(
            sender_sk, 
            recipient_pk, 
            recipient_ciphertext,
            {
                'range_proof': amount_range_proof,
                'equality_proof': amount_equality_proof
            },
            balance_proof  # Will be None if no balance proof
        )
        
        # Transaction with all proofs
        transaction = {
            'sender_pk': sender_pk,
            'recipient_pk': recipient_pk,
            'ciphertext': recipient_ciphertext,
            'amount_proof': {
                'range_proof': amount_range_proof,
                'equality_proof': amount_equality_proof
            },
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
        recipient_address = transaction['recipient_address']
        
        # Reconstruct ciphertext components
        try:
            c1_x = transaction['ciphertext_c1_x']
            c1_y = transaction['ciphertext_c1_y']
            c2_x = transaction['ciphertext_c2_x']
            c2_y = transaction['ciphertext_c2_y']
            
            ciphertext_c1 = ZKPoint(self.curve, c1_x, c1_y)
            ciphertext_c2 = ZKPoint(self.curve, c2_x, c2_y)
            
            # Verify ciphertext points are on the curve
            if not self._is_on_curve(ciphertext_c1) or not self._is_on_curve(ciphertext_c2):
                print("❌ Invalid ciphertext points (not on curve)")
                return False
            
            # Verify ciphertext doesn't represent the identity element (which could be problematic)
            if ciphertext_c1 == 0 * self.G or ciphertext_c2 == 0 * self.G:
                print("❌ Invalid ciphertext (contains identity element)")
                return False
                
        except (KeyError, ValueError, AttributeError) as e:
            print(f"❌ Invalid ciphertext format: {e}")
            return False
        
        # Reconstruct sender public key from address
        try:
            x_str, y_str = sender_address.split(':')
            sender_x = int(x_str)
            sender_y = int(y_str)
            sender_pk = ZKPoint(self.curve, sender_x, sender_y)
            recipient_x, recipient_y = map(int, recipient_address.split(':'))
            recipient_pk = ZKPoint(self.curve, recipient_x, recipient_y)
            
            if not self._is_on_curve(sender_pk):
                print("❌ Invalid sender address (not on curve)")
                return False
                
        except (ValueError, AttributeError) as e:
            print(f"❌ Invalid sender address format: {e}")
            return False
        
        message_components = [
            f"recipient:{recipient_pk.x}:{recipient_pk.y}",
            f"ciphertext_c1:{ciphertext_c1.x}:{ciphertext_c1.y}",
            f"ciphertext_c2:{ciphertext_c2.x}:{ciphertext_c2.y}",
            f"amount_proof_commitment:{amount_proof['range_proof']['commitment'].x}:{amount_proof['range_proof']['commitment'].y}",
            f"amount_equality_proof:{amount_proof['equality_proof']['c']}",
        ]
        
        # If there's a balance proof, include it in the message
        if balance_proof:
            balance_c1, balance_c2 = balance_proof['remaining_balance_ciphertext']
            message_components.append(f"balance_remaining_c1:{balance_c1.x}:{balance_c1.y}")
            message_components.append(f"balance_remaining_c2:{balance_c2.x}:{balance_c2.y}")
            message_components.append(f"balance_proof_commitment:{balance_proof['range_proof']['commitment'].x}:{balance_proof['range_proof']['commitment'].y}")
            message_components.append(f"balance_equality_proof:{balance_proof['equality_proof']['c']}")
            message_components.append(f"balance_subtraction_hash:{balance_proof['subtraction_proof']['hash']}")
        
        # Concatenate all components
        message = ":".join(message_components)
        
        # Verify the signature
        if not self.schnorr_verify_message(sender_pk, signature, message):
            print("❌ Invalid signature")
            return False
        
        if not self.verify_commitment_equality_proof(
            (ciphertext_c1, ciphertext_c2), 
            amount_proof['range_proof']['commitment'], 
            recipient_pk,
            amount_proof['equality_proof']
        ):
            print("❌ Invalid amount equality proof")
            return False
        
        # Then verify the range proof
        if not self.verify_range_proof(amount_proof['range_proof']):
            print("❌ Invalid amount range proof")
            return False
        
        # Step 3: If balance proof provided, verify it
        if transaction['balance_proof']:
            balance_proof = transaction['balance_proof']
            
            # Verify the equality proof for remaining balance
            if not self.verify_commitment_equality_proof(
                balance_proof['remaining_balance_ciphertext'],
                balance_proof['range_proof']['commitment'],
                sender_pk,
                balance_proof['equality_proof']
            ):
                print("❌ Invalid balance equality proof")
                return False
            
            # Verify the range proof for remaining balance
            if not self.verify_range_proof(balance_proof['range_proof']):
                print("❌ Invalid balance range proof")
                return False
            
            # Verify the subtraction relationship
            if not self.verify_subtraction_proof(balance_proof['subtraction_proof']):
                print("❌ Invalid balance subtraction proof")
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