import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.merkle import MerkleTree

class TestMerkleTree(unittest.TestCase):
    def test_empty_tree(self):
        """Test that an empty tree has a valid hash."""
        tree = MerkleTree([])
        self.assertIsNotNone(tree.get_root_hash())
        self.assertEqual(len(tree.get_root_hash()), 64)  # SHA256 is 64 hex chars
    
    def test_single_transaction(self):
        """Test tree with a single transaction."""
        tx = {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10}
        tree = MerkleTree([tx])
        self.assertIsNotNone(tree.get_root_hash())
        self.assertEqual(len(tree.get_root_hash()), 64)
    
    def test_multiple_transactions(self):
        """Test tree with multiple transactions."""
        transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5},
            {'sender': 'Charlie', 'recipient': 'Alice', 'amount': 3}
        ]
        tree = MerkleTree(transactions)
        self.assertIsNotNone(tree.get_root_hash())
        self.assertEqual(len(tree.get_root_hash()), 64)
    
    def test_proof_verification(self):
        """Test that Merkle proofs can be verified."""
        transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5},
            {'sender': 'Charlie', 'recipient': 'Alice', 'amount': 3},
            {'sender': 'Dave', 'recipient': 'Eve', 'amount': 7}
        ]
        tree = MerkleTree(transactions)
        
        # Get proof for tx[1]
        tx_to_verify = transactions[1]
        tx_hash = tree.hash_transaction(tx_to_verify)
        proof = tree.get_proof(tx_to_verify)
        
        # Verify the proof
        self.assertTrue(tree.verify_proof(tx_hash, proof))
        
        # Tamper with the transaction and verify that proof fails
        tampered_tx = dict(tx_to_verify)
        tampered_tx['amount'] = 100
        tampered_hash = tree.hash_transaction(tampered_tx)
        
        self.assertFalse(tree.verify_proof(tampered_hash, proof))
    
    def test_consistency(self):
        """Test that the same transactions produce the same root hash."""
        transactions1 = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5}
        ]
        transactions2 = list(transactions1)  # Create a copy
        
        tree1 = MerkleTree(transactions1)
        tree2 = MerkleTree(transactions2)
        
        self.assertEqual(tree1.get_root_hash(), tree2.get_root_hash())
    
    def test_order_matters(self):
        """Test that transaction order affects the root hash."""
        transactions1 = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5}
        ]
        transactions2 = list(reversed(transactions1))
        
        tree1 = MerkleTree(transactions1)
        tree2 = MerkleTree(transactions2)
        
        self.assertNotEqual(tree1.get_root_hash(), tree2.get_root_hash())


if __name__ == '__main__':
    unittest.main()
