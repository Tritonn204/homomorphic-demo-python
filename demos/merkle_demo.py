import sys
import os
import time
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.merkle import MerkleTree
from blockchain.base import Block

def print_separator():
    print("\n" + "=" * 60)

def create_sample_transactions(num_txs: int = 6) -> List[Dict[str, Any]]:
    """Create sample transactions for demo."""
    transactions = []
    for i in range(num_txs):
        transactions.append({
            'sender': f'User{i}',
            'recipient': f'User{(i+1) % num_txs}',
            'amount': 10 * (i+1),
            'tx_id': f'tx_{i}',
            'timestamp': time.time()
        })
    return transactions

def demonstrate_merkle_tree():
    """Demonstrate Merkle tree functionality."""
    print_separator()
    print("MERKLE TREE DEMO")
    print_separator()
    
    # Create sample transactions
    transactions = create_sample_transactions(6)
    print(f"Created {len(transactions)} sample transactions")
    
    # Create Merkle tree
    print("\nBuilding Merkle tree...")
    tree = MerkleTree(transactions)
    
    # Display root hash
    print(f"\nMerkle Root Hash: {tree.get_root_hash()}")
    print(f"Hash Length: {len(tree.get_root_hash())} characters (SHA-256)")
    
    # Select a transaction to verify
    tx_to_verify = transactions[2]
    print(f"\nVerifying transaction #{transactions.index(tx_to_verify)+1}:")
    print(f"  Sender: {tx_to_verify['sender']}")
    print(f"  Recipient: {tx_to_verify['recipient']}")
    print(f"  Amount: {tx_to_verify['amount']}")
    print(f"  TX ID: {tx_to_verify['tx_id']}")
    
    # Generate proof
    proof = tree.get_proof(tx_to_verify)
    print(f"\nGenerated Merkle Proof with {len(proof)} elements")
    
    # Verify proof
    tx_hash = tree.hash_transaction(tx_to_verify)
    is_valid = tree.verify_proof(tx_hash, proof)
    print(f"\nProof verification: {'✓ VALID' if is_valid else '❌ INVALID'}")
    
    # Demonstrate tampered transaction detection
    print("\n--- Tamper Detection Demo ---")
    tampered_tx = dict(tx_to_verify)
    tampered_tx['amount'] = 999
    print(f"Tampered transaction (changed amount to {tampered_tx['amount']}):")
    
    tampered_hash = tree.hash_transaction(tampered_tx)
    is_valid = tree.verify_proof(tampered_hash, proof)
    print(f"Proof verification: {'✓ VALID (BAD!)' if is_valid else '❌ INVALID (GOOD! Tampering detected)'}")

def demonstrate_merkle_block():
    """Demonstrate Merkle tree integration with blocks."""
    print_separator()
    print("MERKLE BLOCK DEMO")
    print_separator()
    
    # Create sample transactions
    transactions = create_sample_transactions(8)
    print(f"Created {len(transactions)} sample transactions")
    
    # Create a block with these transactions
    print("\nCreating block with Merkle tree...")
    block = Block(1, time.time(), transactions, "prev_hash_123")
    
    # Display block information
    print(f"\nBlock #{block.index}")
    print(f"Merkle Root: {block.merkle_root}")
    print(f"Block Hash: {block.hash}")
    
    # Verify a transaction in the block
    tx_to_verify = transactions[3]
    print(f"\nVerifying transaction {tx_to_verify['tx_id']}...")
    
    is_valid = block.verify_transaction(tx_to_verify)
    print(f"Transaction verification: {'✓ VALID' if is_valid else '❌ INVALID'}")
    
    # Demonstrate tamper detection
    print("\n--- Tamper Detection Demo ---")
    tampered_tx = dict(tx_to_verify)
    tampered_tx['amount'] = 999
    print(f"Tampered transaction (changed amount to {tampered_tx['amount']}):")
    
    is_valid = block.verify_transaction(tampered_tx)
    print(f"Transaction verification: {'✓ VALID (BAD!)' if is_valid else '❌ INVALID (GOOD! Tampering detected)'}")

def run_merkle_demo():
    """Run the Merkle tree and block demos."""
    print("\n==== Merkle Tree Integrity Demo ====\n")
    
    demonstrate_merkle_tree()
    demonstrate_merkle_block()
    
    print_separator()
    print("Merkle Tree Demo Complete!")
    print_separator()

if __name__ == "__main__":
    run_merkle_demo()
