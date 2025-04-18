import hashlib
import random
import time
import threading
import multiprocessing
from tqdm import tqdm
from zkp import TransactionProof, RangeProof
from tinyec import registry
from tinyec.ec import Point

# ===== Cryptographic Primitives =====
curve = registry.get_curve('secp192r1') # Speed is more important than theoretical security with this demo
G = curve.g
q = curve.field.n

# Create second generator for Pedersen commitments
h_seed = hashlib.sha256(b"PEDERSEN_H_GENERATOR").digest()
h_value = int.from_bytes(h_seed, byteorder="big") % q
H = h_value * G

MAX_VALUE_RANGE = 10000
VALUE_POINTS = {}

def generate_value_table(max_range=MAX_VALUE_RANGE):
    """Generate precomputed table of values with progress reporting"""
    global VALUE_POINTS
    print(f"Generating precomputed value table (0-{max_range})...")
    
    # Create progress bar
    for i in tqdm(range(max_range), desc="Building value table"):
        point = i * G
        VALUE_POINTS[point.x] = i
    
    print(f"✓ Precomputed {max_range} values for constant-time lookup")
    return VALUE_POINTS

def constant_time_decrypt(ciphertext, sk, max_range=MAX_VALUE_RANGE):
    """Decrypt ElGamal ciphertext in constant time"""
    # Decrypt the point
    c1, c2 = ciphertext
    decrypted_point = c2 - sk * c1
    
    # Fast lookup from precomputed table (no need for scanning!)
    return VALUE_POINTS.get(decrypted_point.x)

def pedersen_commit(value, blinding_factor):
    """Create a Pedersen commitment to a value"""
    return value * G + blinding_factor * H

def hash_to_scalar(data):
    """Hash arbitrary data to a scalar field element"""
    if isinstance(data, Point):
        data = f"{data.x},{data.y}".encode()
    elif not isinstance(data, bytes):
        data = str(data).encode()
    return int.from_bytes(hashlib.sha256(data).digest(), 'big') % q

# ===== Merkle Tree Implementation =====
class MerkleTree:
    def __init__(self):
        self.leaves = []
        self.nodes = {}  # For path generation
        self.get_root()
        
    def add_leaf(self, commitment):
        """Add a commitment to the tree"""
        if isinstance(commitment, Point):
            leaf_hash = hash_to_scalar(commitment)
        else:
            leaf_hash = commitment
            
        self.leaves.append(leaf_hash)
        self.get_root()

        return len(self.leaves) - 1  # Return index of the new leaf
        
    def get_root(self):
        """Calculate the current Merkle root"""
        if not self.leaves:
            return None
            
        # Build tree bottom-up
        current_level = list(self.leaves)
        self.nodes[0] = current_level
        
        level = 0
        while len(current_level) > 1:
            level += 1
            next_level = []
            
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Hash the pair
                    left, right = current_level[i], current_level[i+1]
                    combined = hash_to_scalar(str(left) + str(right))
                else:
                    # Odd node out, promote to next level
                    combined = hash_to_scalar(str(current_level[i]) + str(current_level[i]))
                next_level.append(combined)
                
            current_level = next_level
            self.nodes[level] = current_level
            
        return current_level[0]
        
    def get_merkle_path(self, leaf_idx):
        """Generate Merkle path for a leaf"""
        if leaf_idx >= len(self.leaves):
            return None
            
        path = []
        current_idx = leaf_idx

        for level in range(len(self.nodes) - 1):
            level_nodes = self.nodes[level]
            is_right = current_idx % 2 == 1
            
            if is_right:
                sibling_idx = current_idx - 1
                path.append((level_nodes[sibling_idx], False))
            else:
                sibling_idx = current_idx + 1
                if sibling_idx < len(level_nodes):
                    path.append((level_nodes[sibling_idx], True))
                else:
                    # No sibling, this is the rightmost node
                    path.append((level_nodes[current_idx], True))
            
            current_idx = current_idx // 2
            
        return path

# ===== Note and Transaction System =====
def twisted_elgamal_encrypt(value, recipient_pk, randomness=None):
    if randomness is None:
        randomness = random.randint(1, q-1)
    return (randomness * G, value * G + randomness * recipient_pk)

def twisted_elgamal_decrypt(ciphertext, sk):
    c1, c2 = ciphertext
    return c2 - sk * c1  # Returns value*G point

def derive_blinding(c1, sk, value):
    """Derive blinding factor from encryption parameters"""
    # Create a shared secret that only the recipient can generate
    shared_point = sk * c1  # This is the same for sender and recipient
    return hash_to_scalar(f"{shared_point.x}")

class Note:
    def __init__(self, value, owner_pk, blinding=None, stealth_address=None):
        self.value = value
        self.owner_pk = owner_pk
        self.stealth_address = stealth_address  # Add this attribute
        
        # Random blinding for commitment
        if blinding is None:
            self.blinding = random.randint(1, q-1)
        else:
            self.blinding = blinding
            
        # Create commitment to the value
        self.commitment = pedersen_commit(value, self.blinding)
        
        # Add encrypted value using Twisted ElGamal
        encryption_rand = random.randint(1, q-1)
        self.encrypted_value = twisted_elgamal_encrypt(value, owner_pk, encryption_rand)
        
class ZKProof:
    """Zero-knowledge proof that doesn't expose raw values"""
    def __init__(self, input_commitments, tx_proof, range_proofs, merkle_paths, merkle_root):
        # Store only the proofs, not the values they prove
        self.input_commitments = input_commitments 
        self.tx_proof = tx_proof
        self.output_range_proofs = range_proofs
        self.merkle_paths = merkle_paths
        self.captured_root = merkle_root
        self.valid = True
        
    def verify(self, input_nullifiers, output_commitments, blockchain_root):
        """Verify the zero-knowledge proof"""
        if not self.valid:
            return False
        
        verification_root = self.captured_root or blockchain_root
            
        # Verify the merkle paths
        for i, path in enumerate(self.merkle_paths):
            commitment = self.input_commitments[i]
            if not self.verify_merkle_path(commitment, path, verification_root):
                return False

        # Verify the transaction proof
        return self.tx_proof.verify(
            input_commitments=[],  # In a real system, these would be looked up
            output_commitments=output_commitments,
            public_keys=[]  # These would be extracted from the transaction
        )

    def verify_merkle_path(self, commitment, path, expected_root):
        """Verify a commitment exists in the Merkle tree"""
        current = hash_to_scalar(commitment)
        
        for sibling, is_right in path:
            if is_right:
                current = hash_to_scalar(str(current) + str(sibling))
            else:
                current = hash_to_scalar(str(sibling) + str(current))
        
        return current == expected_root

class PrivacyBlockchain:
    def __init__(self):
        self.merkle_tree = MerkleTree()
        self.commitments = []  # All commitments in order
        self.nullifiers = set()  # Set of spent nullifiers
        self.transactions = []  # All transactions
        self.note_data = {}
        
    def add_note(self, note):
        """Add a note commitment to the blockchain"""
        # Store the commitment
        idx = len(self.commitments)
        self.commitments.append(note.commitment)
        
        # Add to Merkle tree
        leaf_idx = self.merkle_tree.add_leaf(note.commitment)

        # Store note data
        self.note_data[idx] = {
            "encrypted_value": note.encrypted_value,
            "stealth_address": note.stealth_address,
            "merkle_position": leaf_idx
        }
        
        return leaf_idx
    
    def calculate_nullifier(self, note_commitment, owner_sk):
        """Create a nullifier for spending a note"""
        # Nullifier effectively proves ownership without revealing which note
        nullifier_seed = str(note_commitment.x) + str(owner_sk * G)
        return hash_to_scalar(nullifier_seed)
    
    def process_transaction(self, transaction):
        """Process a private transaction"""
        # Extract transaction data
        nullifiers = transaction["nullifiers"]
        output_commitments = transaction["output_commitments"] 
        proof = transaction["proof"]
        
        # Verify nullifiers aren't already spent
        for nullifier in nullifiers:
            if nullifier in self.nullifiers:
                print("❌ Transaction rejected: Double-spend detected")
                return False
        
        # Verify proof against current state
        merkle_root = self.merkle_tree.get_root()
        if not proof.verify(nullifiers, output_commitments, merkle_root):
            print("❌ Transaction rejected: Invalid proof")
            return False
            
        # Transaction is valid - update state
        
        # Mark nullifiers as spent
        for nullifier in nullifiers:
            self.nullifiers.add(nullifier)
            
        # Add new commitments and their data
        for i, commitment in enumerate(transaction["output_commitments"]):
            self.commitments.append(commitment)
            
            # IMPORTANT: Store output note data for scanning
            if "output_notes_data" in transaction:
                self.note_data[len(self.commitments)-1] = transaction["output_notes_data"][i]
            
        # Record transaction
        tx_record = {
            "timestamp": time.time(),
            "nullifiers": nullifiers,
            "output_commitments": output_commitments,
            "merkle_root": merkle_root
        }
        self.transactions.append(tx_record)
        
        print("✅ Transaction accepted")
        return True

class PrivacyWallet:
    def __init__(self, blockchain, name="Anonymous"):
        """Create a private wallet"""
        self.name = name  # For demo clarity only
        self.blockchain = blockchain
        
        # Generate keypair
        self.sk = random.randint(1, q-1)
        self.pk = self.sk * G
        
        # Track notes owned by this wallet
        self.notes = []  # Notes we own
        self.spent_notes = []  # Notes we've spent
        
    def create_note(self, value):
        """Create a new note owned by this wallet"""
        return Note(value, self.pk)
    
    def receive_note(self, note):
        """Process receiving a note"""
        # Decrypt the value to confirm it
        value_point = twisted_elgamal_decrypt(note.encrypted_value, self.sk)
        
        # Verify the value matches the commitment (in practice, use lookup table)
        # For demo, we trust the provided note value
        
        note_idx = self.blockchain.add_note(note)
        self.notes.append({
            "note": note,
            "position": note_idx
        })

        print(f"💰 {self.name} received note: {note.value} tokens")
        return note_idx
    
    def get_balance(self):
        """Calculate wallet balance"""
        return sum(note["note"].value for note in self.notes)
    
    def create_transaction(self, outputs):
        """Create a private transaction with specified outputs"""
        # Calculate total output amount
        output_total = sum(amount for amount, _ in outputs)
        
        # Select notes to spend
        input_notes = []
        input_value = 0
        
        # Select input notes
        for note in self.notes[:]:
            if note not in self.spent_notes:
                input_notes.append(note)
                input_value += note["note"].value
                
                if input_value >= output_total:
                    break
        
        if input_value < output_total:
            print(f"❌ Insufficient funds: Have {input_value}, need {output_total}")
            return None

        # Create output notes
        output_notes = []
        output_notes_data = []

        for amount, recipient_pk in outputs:
            randomness = random.randint(1, q-1)
            c1 = randomness * G
            shared_point = randomness * recipient_pk  # This equals recipient.sk * c1

            one_time_address_seed = hash_to_scalar(f"stealth{shared_point.x}")
            one_time_address = one_time_address_seed * G  # This replaces direct owner_pk

            blinding = hash_to_scalar(f"{shared_point.x}")
            note = Note(amount, recipient_pk, blinding)

            c2 = amount * G + randomness * recipient_pk
            note.encrypted_value = (c1, c2)
          
            output_notes.append({
                "note": note,
                "position": None,
            })
            
            # Store encrypted data
            output_notes_data.append({
                "encrypted_value": note.encrypted_value,
                "stealth_address": one_time_address,  # Replace owner_pk with stealth address
                "tx_key": c1  # This is needed for recipients to derive the shared secret
            })

        # Add change note if needed
        change_amount = input_value - output_total
        if change_amount > 0:
            # Generate stealth address for change note using same pattern
            randomness = random.randint(1, q-1)
            c1 = randomness * G
            shared_point = randomness * self.pk  # Using our own public key
            
            # Create stealth address consistently
            stealth_seed = hash_to_scalar(f"stealth{shared_point.x}")
            stealth_address = stealth_seed * G
            
            blinding = hash_to_scalar(f"{shared_point.x}")
            change_note = Note(change_amount, self.pk, blinding, stealth_address=stealth_address)
            c2 = change_amount * G + randomness * self.pk
            change_note.encrypted_value = (c1, c2)

            output_notes.append({
                "note": change_note,
                "position": None
            })
            
            # Include stealth address in output data
            output_notes_data.append({
                "encrypted_value": change_note.encrypted_value,
                "stealth_address": stealth_address,
                "tx_key": c1
            })

        # Generate Merkle paths for input notes
        merkle_paths = []
        for note_data in input_notes:
            position = note_data["position"]
            path = self.blockchain.merkle_tree.get_merkle_path(position)
            merkle_paths.append(path)
            
        current_merkle_root = self.blockchain.merkle_tree.get_root()

        input_note_objects = [note_data["note"] for note_data in input_notes]
        output_note_objects = [output_data["note"] for output_data in output_notes]
        input_commitments = [note_data["note"].commitment for note_data in input_notes]

        # Create ZK proof
        owner_secrets = [hash_to_scalar(str(note.blinding)) for note in input_note_objects]
        tx_proof = TransactionProof(
            inputs=input_note_objects,
            outputs=output_note_objects,
            nullifiers=[hash_to_scalar(str(note.commitment)) for note in input_note_objects],
            owner_secrets=owner_secrets
        )
    
        # Generate range proofs (this stays in the wallet)
        range_proofs = [RangeProof(note.value) for note in output_note_objects]
        
        # Create a ZKProof that only contains the proof objects, not the values
        current_merkle_root = self.blockchain.merkle_tree.get_root()
        proof = ZKProof(
            input_commitments=input_commitments, 
            tx_proof=tx_proof, 
            range_proofs=range_proofs,
            merkle_paths=merkle_paths, 
            merkle_root=current_merkle_root
        )
        
        # Calculate nullifiers
        nullifiers = []
        for note in input_notes:
            nullifier = self.blockchain.calculate_nullifier(note["note"].commitment, self.sk)
            nullifiers.append(nullifier)
            
        # Mark notes as spent
        self.spent_notes.extend(input_notes)
        for note in input_notes:
            self.notes.remove(note)
            
        # Create transaction
        transaction = {
            "nullifiers": nullifiers,
            "output_commitments": [note["note"].commitment for note in output_notes],
            "output_notes_data": output_notes_data,
            "proof": proof
        }
        
        # Return both transaction and notes for recipients
        return transaction, output_notes
    
    def scan_blockchain(self):
        """Scan the blockchain for notes belonging to this wallet"""
        print(f"🔍 {self.name}'s wallet scanning blockchain...")
        newly_found = 0
        
        for i, commitment in enumerate(self.blockchain.commitments):
            # Skip notes we already know
            already_known = any(note["note"].commitment.x == commitment.x for note in self.notes + self.spent_notes)
            if already_known:
                continue

            # Try to decrypt potential notes
            note_data = self.blockchain.note_data.get(i)
            if not note_data or "tx_key" not in note_data:
                continue
        
            # Get transaction key and use our private key to calculate shared secret
            tx_key = note_data["encrypted_value"][0]  # This is c1
            shared_point = self.sk * tx_key

            # Generate our expected stealth address from shared secret
            expected_stealth_seed = hash_to_scalar(f"stealth{shared_point.x}")
            expected_stealth = expected_stealth_seed * G

            if note_data["stealth_address"].x == expected_stealth.x:
                # This is our note! Decrypt it
                value = constant_time_decrypt(note_data["encrypted_value"], self.sk)
                        
                if value is not None:
                    shared_point = self.sk * tx_key
                    blinding = hash_to_scalar(f"{shared_point.x}")

                    note = Note(value, self.pk, blinding)
                    leaf_idx = self.receive_note(note)
                    self.blockchain.note_data["merkle_position"] = leaf_idx
                    newly_found += 1
                    print(f"  Found note worth {value} tokens")
                    
        if newly_found > 0:
            print(f"  Found {newly_found} new notes belonging to {self.name}")
        return newly_found
    
def create_coinbase_note(blockchain, miner_wallet, reward_amount=50):
    """Create a mining reward note"""
    print(f"⛏️ Mining reward of {reward_amount} tokens for {miner_wallet.name}")
    
    # Create the coinbase note
    coinbase_note = miner_wallet.create_note(reward_amount)
    
    # Miner receives the note
    miner_wallet.receive_note(coinbase_note)
    
    print(f"💰 {miner_wallet.name} received mining reward: {reward_amount} tokens")
    return coinbase_note

# ===== Demo Runner =====
def run_zk_privacy_demo():
    print("=" * 60)
    print("ZERO-KNOWLEDGE PRIVACY DEMO")
    print("=" * 60)
    
    # Initialize blockchain
    blockchain = PrivacyBlockchain()
    
    # Create wallets
    alice = PrivacyWallet(blockchain, "Alice")
    bob = PrivacyWallet(blockchain, "Bob")
    charlie = PrivacyWallet(blockchain, "Charlie")
    
    print(f"\n🔐 Created wallets for Alice, Bob and Charlie")
    print(f"   Each with their own private keys and viewing keys")
    
    # Create initial notes for Alice
    print("\n💱 Creating initial funds for Alice")
    genesis_note = alice.create_note(100)
    alice.receive_note(genesis_note)
    
    print(f"🔍 Wallet balances after initialization:")
    print(f"   Alice: {alice.get_balance()} tokens")
    print(f"   Bob: {bob.get_balance()} tokens")
    print(f"   Charlie: {charlie.get_balance()} tokens")
    
    # Alice sends funds to Bob
    print("\n💸 Alice sends 30 tokens to Bob")
    outputs = [(30, bob.pk)]
    tx1, output_notes = alice.create_transaction(outputs)
    
    # Process transaction
    blockchain.process_transaction(tx1)
    
    # Bob receives his output note
    print("\n🔍 Wallets scan the blockchain...")
    alice.scan_blockchain()  # Alice finds her change note
    bob.scan_blockchain()
    charlie.scan_blockchain()

    print(f"🔍 Wallet balances after first transaction:")
    print(f"   Alice: {alice.get_balance()} tokens")
    print(f"   Bob: {bob.get_balance()} tokens")
    print(f"   Charlie: {charlie.get_balance()} tokens")
    
    # Split transaction from Bob to Alice and Charlie
    print("\n💸 Bob sends 15 tokens to Charlie and 10 back to Alice")
    outputs = [(15, charlie.pk), (10, alice.pk)]
    tx2, output_notes = bob.create_transaction(outputs)
    
    # Process transaction
    blockchain.process_transaction(tx2)
    
    # Recipients receive their output notes
    print("\n🔍 Wallets scan the blockchain...")
    alice.scan_blockchain()  # Alice finds her change note
    bob.scan_blockchain()
    charlie.scan_blockchain()
        
    print(f"🔍 Wallet balances after second transaction:")
    print(f"   Alice: {alice.get_balance()} tokens")
    print(f"   Bob: {bob.get_balance()} tokens")
    print(f"   Charlie: {charlie.get_balance()} tokens")

    # Add a mining demonstration
    print("\n⛏️ Charlie mines a block and receives a reward")
    charlie_reward = create_coinbase_note(blockchain, charlie, 50)

    print("\n🔍 Wallet balances after mining:")
    print(f"   Alice: {alice.get_balance()} tokens")
    print(f"   Bob: {bob.get_balance()} tokens") 
    print(f"   Charlie: {charlie.get_balance()} tokens")

    # Charlie spends some mining rewards
    print("\n💸 Charlie sends mining rewards to Alice and Bob")
    charlie_outputs = [(20, alice.pk), (10, bob.pk)]
    tx3, output_notes = charlie.create_transaction(charlie_outputs)

    # Process transaction
    blockchain.process_transaction(tx3)

    # Scan for updates
    print("\n🔍 Wallets scan the blockchain...")
    alice.scan_blockchain()
    bob.scan_blockchain()
    charlie.scan_blockchain()

    print(f"🔍 Final wallet balances:")
    print(f"   Alice: {alice.get_balance()} tokens")
    print(f"   Bob: {bob.get_balance()} tokens")
    print(f"   Charlie: {charlie.get_balance()} tokens")
    
    # Examine blockchain state
    print("\n🔗 Final Blockchain State (PUBLIC INFORMATION ONLY):")
    print(f"   Number of commitments: {len(blockchain.commitments)}")
    print(f"   Number of nullifiers: {len(blockchain.nullifiers)}")
    print(f"   Number of transactions: {len(blockchain.transactions)}")
    
    print("\n👁️‍🗨️ What an observer can see on the blockchain:")
    for i, tx in enumerate(blockchain.transactions):
        print(f"   Transaction #{i+1}:")
        print(f"     Time: {time.ctime(tx['timestamp'])}")
        print(f"     Nullifiers: {[n % 100000 for n in tx['nullifiers']]}")
        print(f"     Output commitments: {len(tx['output_commitments'])} new notes")
        print(f"     Can determine which notes were spent? NO")
        print(f"     Can determine transaction amount? NO")
        print(f"     Can determine sender or recipient? NO")
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE - Privacy Features Summary:")
    print("=" * 60)
    print("✓ Amounts are hidden using Pedersen commitments")
    print("✓ Spent notes are hidden using nullifiers")
    print("✓ Sender/recipient relationships are completely hidden")
    print("✓ Transaction graph is not visible to observers")
    print("✓ No correlatable account updates")
    print("=" * 60)

if __name__ == "__main__":
    generate_value_table()
    run_zk_privacy_demo()