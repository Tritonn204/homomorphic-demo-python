import unittest
import sys
import os
import time
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.base import Block, Blockchain
from utils.merkle import MerkleTree


class TestBlock(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10, 'tx_id': '1234'},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5, 'tx_id': '5678'}
        ]
        self.block = Block(1, time.time(), self.transactions, "prev_hash_123")
    
    def test_merkle_root_generation(self):
        """Test that Merkle root is properly generated on block creation."""
        # Manually create a Merkle tree to verify
        tree = MerkleTree(self.transactions)
        expected_root = tree.get_root_hash()
        
        self.assertEqual(self.block.merkle_root, expected_root)
    
    def test_hash_includes_merkle_root(self):
        """Test that block hash calculation includes the Merkle root."""
        # Create a modified block with different transactions
        modified_transactions = list(self.transactions)
        modified_transactions.append({'sender': 'Dave', 'recipient': 'Eve', 'amount': 15, 'tx_id': '9012'})
        
        modified_block = Block(
            self.block.index,
            self.block.timestamp,
            modified_transactions,
            self.block.previous_hash,
            self.block.nonce
        )
        
        # Verify that hash changes due to different Merkle root
        self.assertNotEqual(self.block.hash, modified_block.hash)
        self.assertNotEqual(self.block.merkle_root, modified_block.merkle_root)
    
    def test_block_serialization(self):
        """Test block serialization to and from dict."""
        block_dict = self.block.to_dict()
        
        # Check that merkle_root is included
        self.assertIn('merkle_root', block_dict)
        
        # Recreate block from dict
        recreated_block = Block.from_dict(block_dict)
        
        # Verify block data
        self.assertEqual(recreated_block.index, self.block.index)
        self.assertEqual(recreated_block.timestamp, self.block.timestamp)
        self.assertEqual(recreated_block.transactions, self.block.transactions)
        self.assertEqual(recreated_block.merkle_root, self.block.merkle_root)
        self.assertEqual(recreated_block.hash, self.block.hash)
    
    def test_transaction_verification(self):
        """Test transaction verification using Merkle proofs."""
        # Verify an existing transaction
        tx = self.transactions[0]
        self.assertTrue(self.block.verify_transaction(tx))
        
        # Verify a non-existent transaction
        fake_tx = {'sender': 'Mallory', 'recipient': 'Victim', 'amount': 999, 'tx_id': 'fake'}
        self.assertFalse(self.block.verify_transaction(fake_tx))
        
        # Verify a tampered transaction
        tampered_tx = dict(tx)
        tampered_tx['amount'] = 100
        self.assertFalse(self.block.verify_transaction(tampered_tx))


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.blockchain = Blockchain()
        # Add some transactions
        for i in range(5):
            self.blockchain.add_transaction({
                'sender': f'User{i}',
                'recipient': f'User{i+1}',
                'amount': 10 * (i+1),
                'tx_id': f'tx_{i}'
            })
        # Mine a block
        self.block = self.blockchain.mine_pending_transactions('miner_address')
    
    def test_genesis_block(self):
        """Test that blockchain starts with valid genesis block."""
        self.assertEqual(len(self.blockchain.chain), 2)  # Genesis + mined block
        self.assertEqual(self.blockchain.chain[0].index, 0)
        self.assertEqual(self.blockchain.chain[0].previous_hash, "0")
    
    def test_add_and_mine_transaction(self):
        """Test adding transactions and mining a block."""
        # Add more transactions
        self.blockchain.add_transaction({'sender': 'Alice', 'recipient': 'Bob', 'amount': 50, 'tx_id': 'new_tx'})
        self.blockchain.add_transaction({'sender': 'Charlie', 'recipient': 'Dave', 'amount': 25, 'tx_id': 'new_tx2'})
        
        # Mine the block
        block = self.blockchain.mine_pending_transactions('miner_address')
        
        # Check block was added
        self.assertEqual(len(self.blockchain.chain), 3)
        self.assertEqual(self.blockchain.chain[-1], block)
        self.assertEqual(block.index, 2)
        self.assertEqual(block.previous_hash, self.blockchain.chain[-2].hash)
        
        # Check block contains the transactions
        self.assertEqual(len(block.transactions), 3)  # 2 txs + reward
        self.assertTrue(any(tx.get('tx_id') == 'new_tx' for tx in block.transactions))
        self.assertTrue(any(tx.get('tx_id') == 'new_tx2' for tx in block.transactions))
    
    def test_verify_chain(self):
        """Test blockchain verification."""
        # Valid chain should verify successfully
        self.assertTrue(self.blockchain.verify_chain())
        
        # Tamper with a block and verify the chain fails verification
        self.blockchain.chain[1].transactions[0]['amount'] = 999
        self.blockchain.chain[1].recalculate_merkle_root()  # Update Merkle root
        
        self.assertFalse(self.blockchain.verify_chain())
    
    def test_transaction_verification(self):
        """Test transaction verification across the blockchain."""
        # Add transactions and mine them
        self.blockchain.add_transaction({'sender': 'Alice', 'recipient': 'Bob', 'amount': 50, 'tx_id': 'verify_tx'})
        self.blockchain.mine_pending_transactions('miner_address')
        
        # Verify transaction exists and is valid
        is_valid, block_index, tx_index = self.blockchain.verify_transaction('verify_tx')
        self.assertTrue(is_valid)
        self.assertEqual(block_index, 2)
        
        # Verify non-existent transaction
        is_valid, block_index, tx_index = self.blockchain.verify_transaction('fake_tx')
        self.assertFalse(is_valid)
        self.assertIsNone(block_index)
        self.assertIsNone(tx_index)
    
    def test_blockchain_serialization(self):
        """Test blockchain serialization to and from dict."""
        # Serialize the blockchain
        blockchain_dict = self.blockchain.to_dict()
        
        # Check that blocks have merkle_root
        self.assertIn('merkle_root', blockchain_dict['chain'][0])
        
        # Save to JSON
        json_data = json.dumps(blockchain_dict)
        
        # Recreate from JSON
        loaded_dict = json.loads(json_data)
        recreated_blockchain = Blockchain.from_dict(loaded_dict)
        
        # Verify blockchain data
        self.assertEqual(len(recreated_blockchain.chain), len(self.blockchain.chain))
        self.assertEqual(recreated_blockchain.chain[0].hash, self.blockchain.chain[0].hash)
        self.assertEqual(recreated_blockchain.chain[1].hash, self.blockchain.chain[1].hash)
        
        # Verify merkle roots were preserved
        self.assertEqual(recreated_blockchain.chain[1].merkle_root, self.blockchain.chain[1].merkle_root)


if __name__ == '__main__':
    unittest.main()
