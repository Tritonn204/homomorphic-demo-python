import random
import hashlib
import time
from tinyec import registry
from tinyec.ec import Point

# System setup
curve = registry.get_curve('secp256r1')
G = curve.g
q = curve.field.n

# Second generator for Pedersen
h_seed = hashlib.sha256(b"PEDERSEN_H_GENERATOR").digest()
h_value = int.from_bytes(h_seed, byteorder="big") % q
H = h_value * G

G_TABLE = {i: i * G for i in range(100)}
LOOKUP_G = {(i * G).x: i for i in range(100)}  # Simple lookup by x-coordinate

# Basic crypto functions from before (pedersen_commit, etc.)
def pedersen_commit(value, blinding_factor):
    return value * G + blinding_factor * H

def twisted_elgamal_keygen():
    sk = random.randint(1, q-1)
    pk = sk * G
    return (sk, pk)

def twisted_elgamal_encrypt(amount, recipient_pk, randomness=None):
    if randomness is None:
        randomness = random.randint(1, q-1)
    return (randomness * G, amount * G + randomness * recipient_pk)

def twisted_elgamal_decrypt(ciphertext, sk):
    c1, c2 = ciphertext
    amount_point = c2 - sk * c1
    
    # In a real system, we might use more sophisticated methods to extract amount
    # This is a simplified approach for small values
    for i in range(100):
        if G_TABLE[i].x == amount_point.x:
            return i
    return None  # Cannot determine exact amount

# New: Stealth address generation for recipient privacy
def generate_stealth_address(recipient_view_pk, recipient_spend_pk):
    r = random.randint(1, q-1)  # One-time random value
    R = r * G  # Public value sent with transaction
    
    # Shared secret - only recipient can compute this
    shared_secret_point = r * recipient_view_pk
    shared_secret = shared_secret_point.x.to_bytes(32, 'big')
    
    # Derive one-time address
    hash_input = shared_secret + b"stealth_derivation"
    hash_output = int.from_bytes(hashlib.sha256(hash_input).digest(), 'big') % q
    
    # One-time public key that only recipient can recognize and spend from
    one_time_pk = recipient_spend_pk + hash_output * G
    
    return (R, one_time_pk)

# New: Simple ring signature (greatly simplified for demo purposes)
def create_ring_signature(message, signer_key, public_keys):
    # In a real system, this would be much more complex
    n = len(public_keys)
    
    # Find the position of the signer in the ring
    signer_idx = -1
    for i, pk in enumerate(public_keys):
        if pk.x == (signer_key * G).x and pk.y == (signer_key * G).y:
            signer_idx = i
            break
    
    if signer_idx == -1:
        raise ValueError("Signer not in the ring")
    
    # Generate random values for each public key except signer
    c = [0] * n
    r = [0] * n
    
    # Start with a random c[0]
    c[0] = random.randint(1, q-1)
    
    # For each public key except the signer's
    for i in range(n):
        if i != signer_idx:
            r[i] = random.randint(1, q-1)
            next_idx = (i + 1) % n
            # This is a simplified version - real ring sigs use more complex math
            hash_input = str(message + str((r[i] * G).x) + str((c[i] * public_keys[i]).x)).encode()
            c[next_idx] = int.from_bytes(hashlib.sha256(hash_input).digest(), 'big') % q
    
    # Complete the ring with signer's key
    hash_input = str(message + str((r[n-1] * G).x) + str((c[n-1] * public_keys[n-1]).x)).encode() 
    last_c = int.from_bytes(hashlib.sha256(hash_input).digest(), 'big') % q
    
    # Solve for r[signer_idx]
    r[signer_idx] = (last_c * signer_key) % q
    
    return (c[0], r)

def verify_ring_signature(message, signature, public_keys):
    # Simplified verification - in a real system this would be more complex
    return True  # For demo purposes

class AccountWithFullPrivacy:
    def __init__(self, name, initial_balance):
        # PRIVATE keys
        self.name = name  # For demo clarity only
        self.balance = initial_balance
        self.blinding_factor = random.randint(1, q-1)
        
        # Key pairs
        self.spend_sk = random.randint(1, q-1)
        self.spend_pk = self.spend_sk * G
        
        self.view_sk = random.randint(1, q-1)
        self.view_pk = self.view_sk * G
        
        # Commitments known to blockchain
        self.commitment = pedersen_commit(initial_balance, self.blinding_factor)
        
        # For tracking one-time keys we control
        self.controlled_keys = []
        
        print(f"✅ Created account {name}")
        print(f"  [PRIVATE] Initial balance: {initial_balance}")
        print(f"  [PUBLIC] Commitment: ({self.commitment.x}, {self.commitment.y})")
        print(f"  [PUBLIC] View public key: ({self.view_pk.x}, {self.view_pk.y})")
        print(f"  [PUBLIC] Spend public key: ({self.spend_pk.x}, {self.spend_pk.y})\n")
    
    def create_transfer(self, amount, recipient, decoy_accounts, blockchain):
        print(f"🔄 Creating fully private transfer")
        print(f"  [PRIVATE TO SENDER] Amount to send: {amount}")
        print(f"  [PRIVATE TO SENDER] Current balance: {self.balance}")
        
        # 1. Create stealth address for recipient
        R, one_time_pk = generate_stealth_address(recipient.view_pk, recipient.spend_pk)
        
        # 2. Create new commitment for reduced balance
        new_balance = self.balance - amount
        new_blinding = random.randint(1, q-1)
        new_commitment = pedersen_commit(new_balance, new_blinding)
        
        # 3. Create commitment for transfer amount
        amount_blinding = random.randint(1, q-1)
        amount_commitment = pedersen_commit(amount, amount_blinding)
        
        # 4. Encrypt amount for recipient (only they can decrypt)
        # In a real system, would use proper encryption and range proofs
        encrypted_amount = str(amount).encode()  # Simplified for demo
        
        # 5. Create ring signature (hide which account is the sender)
        # Get public keys for the ring (including self)
        ring_public_keys = [self.spend_pk]
        for account in decoy_accounts:
            ring_public_keys.append(account.spend_pk)
        random.shuffle(ring_public_keys)  # Randomize order
        
        # Create ring signature
        message = str(one_time_pk.x) + str(amount_commitment.x)
        ring_signature = create_ring_signature(message, self.spend_sk, ring_public_keys)
        
        # Update sender's private state
        self.balance = new_balance
        self.blinding_factor = new_blinding
        
        # For demo purposes, we'll track which one-time key is being used
        recipient.remember_one_time_key(one_time_pk, R, amount)
            
        # Create transaction with only PUBLIC information
        tx = {
            "timestamp": time.time(),
            "ring_members": ring_public_keys,  # Public keys that could be the sender
            "ring_signature": ring_signature,  # Proves one ring member signed without revealing which
            "stealth_address": one_time_pk,    # One-time destination, not linked to recipient
            "R": R,                            # Value for recipient to derive private key
            "amount_commitment": amount_commitment,  # Committed amount (hidden)
            "encrypted_data": encrypted_amount  # Only recipient can decrypt
        }
        
        # Submit to blockchain
        return blockchain.process_anonymous_tx(tx)
    
    def remember_one_time_key(self, one_time_pk, R, amount):
        # In a real system, the recipient would scan the blockchain
        # and try to derive each one-time key to see if it's theirs
        self.controlled_keys.append({
            "one_time_pk": one_time_pk,
            "R": R,
            "amount": amount,
            "spent": False
        })
    
    def check_for_received_funds(self, blockchain):
        print(f"🔍 {self.name} scanning blockchain for received funds")
        
        new_funds = 0
        
        # In a real system, the recipient would scan the blockchain
        # using their view key to identify transactions sent to them
        for key_data in self.controlled_keys:
            if not key_data["spent"]:
                new_funds += key_data["amount"]
                key_data["spent"] = True
        
        if new_funds > 0:
            # Update balance
            old_balance = self.balance
            self.balance += new_funds
            
            # New commitment
            new_blinding = random.randint(1, q-1)
            self.blinding_factor = new_blinding
            self.commitment = pedersen_commit(self.balance, self.blinding_factor)
            
            print(f"  [PRIVATE TO {self.name}] Found {new_funds} new funds")
            print(f"  [PRIVATE TO {self.name}] Balance updated: {old_balance} → {self.balance}")
            print(f"  [PUBLIC] New commitment: ({self.commitment.x}, {self.commitment.y})\n")
            
            # No explicit receipt - just update commitment
            blockchain.update_commitment(self.name, self.commitment)
        else:
            print(f"  No new funds found\n")

class FullPrivacyBlockchain:
    def __init__(self):
        self.accounts = {}  # Only commitment is stored
        self.transactions = []  # Anonymous transaction log
        print("🔗 Private Blockchain initialized\n")
        
    def register_account(self, account):
        # Blockchain only knows the public keys and commitment, not the account owner
        self.accounts[account.name] = {
            "commitment": account.commitment,
            "view_pk": account.view_pk,
            "spend_pk": account.spend_pk
        }
        print(f"📝 Registered account (public keys only)\n")
    
    def process_anonymous_tx(self, tx):
        # In a full-privacy blockchain, we don't know sender or recipient
        tx_id = len(self.transactions) + 1
        tx["tx_id"] = tx_id
        
        print(f"🔗 Recording anonymous transaction #{tx_id}")
        print(f"  [PUBLIC] Transaction with ring size: {len(tx['ring_members'])}")
        print(f"  [PUBLIC] Using one-time stealth address")
        print(f"  [PUBLIC] Amount: [COMMITTED & ENCRYPTED]\n")
        
        self.transactions.append(tx)
        return tx
    
    def update_commitment(self, account_name, new_commitment):
        # Account updates its commitment (e.g., after receiving funds)
        self.accounts[account_name]["commitment"] = new_commitment
        print(f"🔗 Account updated its commitment\n")
    
    def print_state(self):
        print("\n🔍 BLOCKCHAIN STATE (ALL PUBLIC INFORMATION):")
        print("-" * 50)
        
        print("ACCOUNT PUBLIC KEYS & COMMITMENTS:")
        for name, data in self.accounts.items():
            print(f"  Account public info:")
            print(f"    Commitment: ({data['commitment'].x}, {data['commitment'].y})")
            print(f"    Public keys: [view, spend]")
        
        print("\nANONYMOUS TRANSACTION HISTORY:")
        for tx in self.transactions:
            print(f"  TX #{tx['tx_id']} | {time.ctime(tx['timestamp'])}")
            print(f"  Ring size: {len(tx['ring_members'])}")
            print(f"  Using stealth address: ({tx['stealth_address'].x}, {tx['stealth_address'].y})")
            print(f"  Amount: [COMMITTED & ENCRYPTED]")
        print("-" * 50)

def run_full_privacy_demo():
    print("=" * 50)
    print("FULL PRIVACY DEMO WITH RING SIGNATURES & STEALTH ADDRESSES")
    print("=" * 50)
    
    # Setup blockchain
    blockchain = FullPrivacyBlockchain()
    
    # Create accounts
    alice = AccountWithFullPrivacy("Alice", 50)
    bob = AccountWithFullPrivacy("Bob", 30)
    
    # Create some decoy accounts for the ring
    charlie = AccountWithFullPrivacy("Charlie", 100)
    dave = AccountWithFullPrivacy("Dave", 75)
    eve = AccountWithFullPrivacy("Eve", 60)
    
    # Register accounts
    for account in [alice, bob, charlie, dave, eve]:
        blockchain.register_account(account)
    
    # Transaction: Someone sends funds to someone else (we don't know who)
    print("\nTRANSACTION 1: Alice sends 20 to Bob (but blockchain doesn't know this)")
    decoys = [charlie, dave, eve]
    tx1 = alice.create_transfer(20, bob, decoys, blockchain)
    
    # Bob checks for received funds
    bob.check_for_received_funds(blockchain)
    
    # Transaction 2: Bob sends funds back
    print("\nTRANSACTION 2: Bob sends 5 back to Alice (but blockchain doesn't know this)")
    tx2 = bob.create_transfer(5, alice, decoys, blockchain)
    
    # Alice checks for received funds
    alice.check_for_received_funds(blockchain)
    
    # Print final state
    blockchain.print_state()
    
    print("\n" + "=" * 50)
    print("FULL PRIVACY DEMO COMPLETE")
    print("=" * 50)
    print("Key privacy features demonstrated:")
    print("1. Ring signatures hide the sender among decoys")
    print("2. Stealth addresses hide the recipient")
    print("3. Pedersen commitments hide the amounts")
    print("4. No transaction graph is visible to outside observers")

if __name__ == "__main__":
    run_full_privacy_demo()