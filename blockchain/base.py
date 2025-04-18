import hashlib
import time
import json
import sys
import os
from typing import List, Dict, Any, Optional

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.merkle import MerkleTree

class Block:
    """Basic block structure for the blockchain."""
    def __init__(self, index: int, timestamp: float, transactions: List[Dict[str, Any]], 
                 previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_tree = MerkleTree(transactions)
        self.merkle_root = self.merkle_tree.get_root_hash()
        self.hash = self.calculate_hash()
        
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the block data using a Merkle root."""
        block_data = {
            'index': self.index,
            'timestamp': self.timestamp,
            'merkle_root': self.merkle_root,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def recalculate_merkle_root(self) -> None:
        """Recalculate Merkle root for block transactions."""
        self.merkle_tree = MerkleTree(self.transactions)
        self.merkle_root = self.merkle_tree.get_root_hash()
        self.hash = self.calculate_hash()
    
    def mine_block(self, difficulty: int = 2) -> None:
        """Mine a block by finding a hash with leading zeros."""
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to a serializable dictionary."""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'hash': self.hash
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Block':
        """Create a Block instance from a dictionary."""
        block = Block(
            data['index'],
            data['timestamp'],
            data['transactions'],
            data['previous_hash'],
            data['nonce']
        )
        # Handle backward compatibility for blocks lacking merkle_root
        if 'merkle_root' in data:
            block.merkle_root = data['merkle_root']
        else:
            block.recalculate_merkle_root()
            
        block.hash = data['hash']
        return block
    
    def verify_transaction(self, transaction: Dict[str, Any]) -> bool:
        """Verify that a transaction exists in this block using Merkle proof."""
        if transaction not in self.transactions:
            return False
        
        # Calculate the transaction hash
        tx_string = json.dumps(transaction, sort_keys=True).encode()
        tx_hash = hashlib.sha256(tx_string).hexdigest()
        
        # Get the Merkle proof
        proof = self.merkle_tree.get_proof(transaction)
        
        # Verify the proof
        return self.merkle_tree.verify_proof(tx_hash, proof)


class Blockchain:
    """Simple blockchain implementation that can store transactions."""
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.create_genesis_block()
        self.difficulty = 2
    
    def create_genesis_block(self) -> None:
        """Create the initial block in the chain."""
        genesis_block = Block(0, time.time(), [], "0")
        self.chain.append(genesis_block)
        
    def get_latest_block(self) -> Block:
        """Get the most recently added block."""
        return self.chain[-1]
    
    def add_transaction(self, transaction: Dict[str, Any]) -> bool:
        """Add a new transaction to pending transactions list."""
        self.pending_transactions.append(transaction)
        return True
    
    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        """Create a new block with pending transactions and mine it."""
        if not self.pending_transactions:
            print("No pending transactions to mine")
            return None
        
        # Create a mining reward transaction (simplified)
        reward_tx = {
            'sender': 'BLOCKCHAIN_REWARD',
            'recipient': miner_address,
            'amount': 1.0,
            'timestamp': time.time()
        }
        
        # Add reward transaction to list
        transactions = self.pending_transactions + [reward_tx]
        
        # Create new block
        latest_block = self.get_latest_block()
        block = Block(
            latest_block.index + 1,
            time.time(),
            transactions,
            latest_block.hash
        )
        
        # Mine the block
        block.mine_block(self.difficulty)
        
        # Add new block to chain
        self.chain.append(block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        return block
    
    def verify_chain(self) -> bool:
        """Verify that the blockchain is valid."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify block hash
            if current_block.hash != current_block.calculate_hash():
                print(f"Hash mismatch on block {i}")
                return False
            
            # Verify chain integrity
            if current_block.previous_hash != previous_block.hash:
                print(f"Chain broken at block {i}")
                return False
            
            # Verify Merkle root is valid
            merkle_tree = MerkleTree(current_block.transactions)
            if current_block.merkle_root != merkle_tree.get_root_hash():
                print(f"Merkle root mismatch on block {i}")
                return False
        
        return True
        
    def verify_transaction(self, tx_id: str) -> tuple:
        """Verify a transaction exists in the blockchain and is valid.
        
        Args:
            tx_id: Transaction ID to verify
            
        Returns:
            tuple: (is_valid, block_index, tx_index) or (False, None, None) if not found
        """
        for block in self.chain:
            for i, tx in enumerate(block.transactions):
                if tx.get('tx_id') == tx_id:
                    # Found transaction, verify its inclusion using Merkle proofs
                    is_valid = block.verify_transaction(tx)
                    return is_valid, block.index, i
        
        return False, None, None
    
    def scan_for_transactions(self, address: str) -> List[Dict[str, Any]]:
        """Scan the blockchain for transactions involving an address."""
        transactions = []
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('sender') == address or tx.get('recipient') == address:
                    transactions.append({
                        'block_index': block.index,
                        'block_hash': block.hash,
                        'transaction': tx
                    })
        
        return transactions
    
    def get_balance(self, address: str) -> float:
        """Calculate the balance of an address from blockchain transactions."""
        balance = 0.0
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('recipient') == address:
                    balance += float(tx.get('amount', 0))
                if tx.get('sender') == address:
                    balance -= float(tx.get('amount', 0))
        
        return balance
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert blockchain to serializable dictionary."""
        return {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.pending_transactions,
            'difficulty': self.difficulty
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Blockchain':
        """Create a Blockchain instance from a dictionary."""
        blockchain = Blockchain()
        blockchain.chain = [Block.from_dict(block_data) for block_data in data['chain']]
        blockchain.pending_transactions = data['pending_transactions']
        blockchain.difficulty = data['difficulty']
        return blockchain
    
    def save_to_file(self, filename: str) -> None:
        """Save blockchain to a JSON file."""
        with open(filename, 'w') as file:
            json.dump(self.to_dict(), file, indent=2)
    
    @staticmethod
    def load_from_file(filename: str) -> 'Blockchain':
        """Load blockchain from a JSON file."""
        with open(filename, 'r') as file:
            data = json.load(file)
            return Blockchain.from_dict(data)
