import random
import time
import hashlib
from tinyec import registry
from tinyec.ec import Point

# Use a standard curve
curve = registry.get_curve('secp256r1')
G = curve.g
q = curve.field.n

# Create second generator H
h_seed = hashlib.sha256(b"PEDERSEN_H_GENERATOR").digest()
h_value = int.from_bytes(h_seed, byteorder="big") % q
H = h_value * G

print(f"System setup complete:")
print(f"Curve: {curve.name}")
print(f"G: ({G.x}, {G.y})")
print(f"H: ({H.x}, {H.y})\n")

# For simplicity: Tables for small values to help with "discrete log" problem
G_TABLE = {i: i * G for i in range(100)}
LOOKUP_G = {(i * G).x: i for i in range(100)}  # Simple lookup by x-coordinate

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

class Account:
    def __init__(self, name, initial_balance):
        # PRIVATE: Only known to the account owner
        self.name = name
        self.balance = initial_balance
        self.blinding_factor = random.randint(1, q-1)
        self.sk, self.pk = twisted_elgamal_keygen()
        
        # PUBLIC: Visible on blockchain
        self.commitment = pedersen_commit(initial_balance, self.blinding_factor)
        
        print(f"✅ Created account {name}")
        print(f"  [PRIVATE TO {name}] Initial balance: {initial_balance}")
        print(f"  [PUBLIC] Commitment: ({self.commitment.x}, {self.commitment.y})")
        print(f"  [PUBLIC] Public key: ({self.pk.x}, {self.pk.y})\n")
        
    def create_transfer(self, amount, recipient):
        # PRIVATE to sender: amount, new_balance, new_blinding
        print(f"🔄 {self.name} creating transfer")
        print(f"  [PRIVATE TO {self.name}] Amount to send: {amount}")
        print(f"  [PRIVATE TO {self.name}] Current balance: {self.balance}")
        
        new_balance = self.balance - amount
        new_blinding = random.randint(1, q-1)
        
        # PUBLIC: Visible to blockchain
        new_commitment = pedersen_commit(new_balance, new_blinding)
        amount_ciphertext = twisted_elgamal_encrypt(amount, recipient.pk)
        
        print(f"  [PUBLIC] Old commitment: ({self.commitment.x}, {self.commitment.y})")
        print(f"  [PUBLIC] New commitment: ({new_commitment.x}, {new_commitment.y})")
        print(f"  [PUBLIC] Amount ciphertext: [encrypted]")
        
        # This would normally include zero-knowledge proofs that:
        # 1. The amount is positive
        # 2. The sender has sufficient balance
        # 3. The new commitment correctly reflects the balance after subtraction
        
        # Update sender's private state
        self.balance = new_balance
        self.blinding_factor = new_blinding
        self.commitment = new_commitment
        print(f"  [PRIVATE TO {self.name}] New balance: {self.balance}\n")
        
        # Return only PUBLIC information for the blockchain
        return {
            "sender": self.name,
            "recipient": recipient.name,
            "old_commitment": self.commitment,
            "new_commitment": new_commitment,
            "amount_ciphertext": amount_ciphertext
        }
        
    def receive_transfer(self, tx):
        print(f"📥 {self.name} receiving transfer in TX #{tx['tx_id']}")
        
        # PRIVATE: Decrypt the amount using private key
        c1, c2 = tx["amount_ciphertext"]
        decrypted_amount = twisted_elgamal_decrypt((c1, c2), self.sk)
        
        if decrypted_amount is None:
            print(f"  [PRIVATE TO {self.name}] Unable to decrypt exact amount")
            # For demo purposes only:
            decrypted_amount = int(input(f"  Enter amount for demo purposes: "))
        else:
            print(f"  [PRIVATE TO {self.name}] Decrypted amount: {decrypted_amount}")
            
        # Update receiver's private state
        old_balance = self.balance
        self.balance += decrypted_amount
        new_blinding = random.randint(1, q-1)
        
        # PUBLIC: Create new commitment for updated balance
        new_commitment = pedersen_commit(self.balance, new_blinding)
        self.blinding_factor = new_blinding
        self.commitment = new_commitment
        
        print(f"  [PRIVATE TO {self.name}] Old balance: {old_balance}")
        print(f"  [PRIVATE TO {self.name}] New balance: {self.balance}")
        print(f"  [PUBLIC] New commitment: ({new_commitment.x}, {new_commitment.y})\n")
        
        # Return only PUBLIC information for the blockchain
        return {
            "tx_id": tx["tx_id"],
            "recipient": self.name,
            "sender": tx["sender"],
            "new_commitment": new_commitment
        }

class Blockchain:
    def __init__(self):
        self.accounts = {}  # Account commitments
        self.transactions = []  # Transaction log
        print("🔗 Blockchain initialized\n")
        
    def register_account(self, account):
        self.accounts[account.name] = {"commitment": account.commitment}
        print(f"📝 Blockchain: Registered account {account.name}\n")
    
    def process_tx(self, tx):
        # Create transaction record with metadata
        tx_record = {
            "tx_id": len(self.transactions) + 1,
            "timestamp": time.time(),
            "sender": tx["sender"],
            "recipient": tx["recipient"],
            "amount_ciphertext": tx["amount_ciphertext"],  # Encrypted amount
            "sender_old_commitment": tx["old_commitment"],
            "sender_new_commitment": tx["new_commitment"],
            "status": "pending_receipt"
        }
        
        print(f"🔗 Blockchain recording transaction #{tx_record['tx_id']}")
        print(f"  [PUBLIC] Sender: {tx_record['sender']}")
        print(f"  [PUBLIC] Recipient: {tx_record['recipient']}")
        print(f"  [PUBLIC] Timestamp: {time.ctime(tx_record['timestamp'])}")
        print(f"  [PUBLIC BUT ENCRYPTED] Amount ciphertext: (encrypted)")
        
        # Update sender's commitment
        self.accounts[tx["sender"]]["commitment"] = tx["new_commitment"]
        print(f"  [PUBLIC] Updated sender commitment on blockchain\n")
        
        # Record transaction
        self.transactions.append(tx_record)
        
        # Return data needed for recipient
        return {
            "tx_id": tx_record["tx_id"],
            "sender": tx_record["sender"],
            "recipient": tx_record["recipient"],
            "amount_ciphertext": tx_record["amount_ciphertext"]
        }
    
    def confirm_receipt(self, receipt):
        tx_id = receipt["tx_id"]
        print(f"🔗 Blockchain recording receipt confirmation for TX #{tx_id}")
        print(f"  [PUBLIC] {receipt['recipient']} confirmed receiving from {receipt['sender']}")
        
        # Update recipient's commitment
        self.accounts[receipt["recipient"]]["commitment"] = receipt["new_commitment"]
        
        # Update transaction status
        for tx in self.transactions:
            if tx["tx_id"] == tx_id:
                tx["status"] = "completed"
                tx["recipient_new_commitment"] = receipt["new_commitment"]
                break
        
        print(f"  [PUBLIC] Updated recipient commitment on blockchain")
        print(f"  [PUBLIC] Transaction #{tx_id} marked as completed\n")
    
    def print_state(self):
        print("\n🔍 CURRENT BLOCKCHAIN STATE (ALL PUBLIC INFORMATION):")
        print("-" * 50)
        
        print("ACCOUNTS:")
        for name, data in self.accounts.items():
            commitment = data["commitment"]
            print(f"  {name}: Commitment=({commitment.x}, {commitment.y})")
        
        print("\nTRANSACTION HISTORY:")
        for tx in self.transactions:
            print(f"  TX #{tx['tx_id']} | {time.ctime(tx['timestamp'])}")
            print(f"    Sender: {tx['sender']} → Recipient: {tx['recipient']}")
            print(f"    Status: {tx['status']}")
            print(f"    Amount: [ENCRYPTED]")
        print("-" * 50)

def run_demo():
    print("=" * 50)
    print("PRIVATE BALANCE DEMO WITH PEDERSEN + TWISTED ELGAMAL")
    print("=" * 50)
    print("This demo clearly distinguishes between:")
    print("- [PRIVATE] information (only known to the owner)")
    print("- [PUBLIC] information (visible on the blockchain)\n")
    
    # Setup blockchain
    blockchain = Blockchain()
    
    # Create accounts
    alice = Account("Alice", 50)
    bob = Account("Bob", 30)
    
    # Register accounts
    blockchain.register_account(alice)
    blockchain.register_account(bob)
    
    # Print initial state
    blockchain.print_state()
    
    # Transaction 1: Alice sends 20 to Bob
    print("TRANSACTION 1: Alice sends 20 to Bob")
    # Alice creates and submits transfer
    tx1 = alice.create_transfer(20, bob)
    processed_tx1 = blockchain.process_tx(tx1)
    
    # Bob receives and processes the transfer
    receipt1 = bob.receive_transfer(processed_tx1)
    blockchain.confirm_receipt(receipt1)
    
    # Print state after first transaction
    blockchain.print_state()
    
    # Transaction 2: Bob sends 5 back to Alice
    print("TRANSACTION 2: Bob sends 5 to Alice")
    # Bob creates and submits transfer
    tx2 = bob.create_transfer(5, alice)
    processed_tx2 = blockchain.process_tx(tx2)
    
    # Alice receives and processes the transfer
    receipt2 = alice.receive_transfer(processed_tx2)
    blockchain.confirm_receipt(receipt2)
    
    # Print final state
    blockchain.print_state()
    
    print("=" * 50)
    print("DEMO COMPLETE")
    print("=" * 50)

if __name__ == "__main__":
    run_demo()