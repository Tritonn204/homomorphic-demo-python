import hashlib
import json
from typing import List, Dict, Any, Optional, Union
from zkp.zk_pedersen_elgamal import ZKProofEncoder

class MerkleNode:
    """Node in a Merkle tree."""
    def __init__(self, hash_value: str, left=None, right=None, data=None):
        self.hash_value = hash_value
        self.left = left
        self.right = right
        self.data = data  # Optional data for leaf nodes

    def is_leaf(self) -> bool:
        """Return True if this is a leaf node."""
        return self.left is None and self.right is None


class MerkleTree:
    """
    Implementation of a Merkle tree for transaction verification.
    
    A Merkle tree is a binary tree where each leaf node is a hash of a transaction,
    and each non-leaf node is a hash of its two child nodes.
    """
    def __init__(self, transactions: List[Dict[str, Any]] = None):
        self.root = None
        if transactions:
            self.build_tree(transactions)
    
    def hash_transaction(self, transaction: Dict[str, Any]) -> str:
        """Hash a transaction dictionary."""
        tx_string = json.dumps(transaction, sort_keys=True, cls=ZKProofEncoder).encode()
        return hashlib.sha256(tx_string).hexdigest()
    
    def hash_pair(self, left_hash: str, right_hash: str) -> str:
        """Hash two child hashes together."""
        combined = (left_hash + right_hash).encode()
        return hashlib.sha256(combined).hexdigest()
    
    def build_tree(self, transactions: List[Dict[str, Any]]) -> None:
        """Build a Merkle tree from a list of transactions."""
        if not transactions:
            self.root = MerkleNode(hashlib.sha256(b"").hexdigest())
            return
        
        # Create leaf nodes for transactions
        leaves = []
        for tx in transactions:
            tx_hash = self.hash_transaction(tx)
            node = MerkleNode(tx_hash, data=tx)
            leaves.append(node)
        
        # If odd number of transactions, duplicate the last one
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        
        # Build tree from bottom up
        self.root = self._build_tree_recursive(leaves)
    
    def _build_tree_recursive(self, nodes: List[MerkleNode]) -> Optional[MerkleNode]:
        """Recursively build the Merkle tree from leaf nodes up."""
        if not nodes:
            return None
        
        if len(nodes) == 1:
            return nodes[0]
        
        # Create new level of nodes
        new_level = []
        
        # Process pairs of nodes
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            # If we have odd number, duplicate the last node
            right = nodes[i+1] if i+1 < len(nodes) else left
            
            # Create parent node with combined hash
            parent_hash = self.hash_pair(left.hash_value, right.hash_value)
            parent = MerkleNode(parent_hash, left=left, right=right)
            new_level.append(parent)
        
        # Recursively build the next level
        return self._build_tree_recursive(new_level)
    
    def get_root_hash(self) -> str:
        """Get the Merkle root hash."""
        if self.root:
            return self.root.hash_value
        return hashlib.sha256(b"").hexdigest()
    
    def get_proof(self, transaction: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generate a Merkle proof for a transaction.
        
        Each element in the proof is a dict with 'position' ('left' or 'right')
        and 'hash' fields.
        """
        tx_hash = self.hash_transaction(transaction)
        proof = []
        
        if not self.root:
            return proof
        
        # Find the transaction leaf node
        current_nodes = [self.root]
        found_path = []
        
        # Use breadth-first search to find the transaction
        while current_nodes:
            next_nodes = []
            for node in current_nodes:
                if node.is_leaf() and node.hash_value == tx_hash:
                    # Found the transaction leaf
                    return self._generate_proof(found_path, tx_hash)
                
                if node.left:
                    found_path.append((node, 'left'))
                    next_nodes.append(node.left)
                if node.right:
                    found_path.append((node, 'right'))
                    next_nodes.append(node.right)
            
            current_nodes = next_nodes
        
        return proof  # Transaction not found
    
    def _generate_proof(self, found_path: List[tuple], tx_hash: str) -> List[Dict[str, str]]:
        """Generate a Merkle proof from the found path."""
        proof = []
        
        # Trace back up the path
        for node, direction in reversed(found_path):
            if direction == 'left' and node.left and node.left.hash_value == tx_hash:
                if node.right:
                    proof.append({'position': 'right', 'hash': node.right.hash_value})
                tx_hash = node.hash_value
            elif direction == 'right' and node.right and node.right.hash_value == tx_hash:
                if node.left:
                    proof.append({'position': 'left', 'hash': node.left.hash_value})
                tx_hash = node.hash_value
        
        return proof
    
    def verify_proof(self, tx_hash: str, proof: List[Dict[str, str]]) -> bool:
        """
        Verify a Merkle proof for a transaction hash.
        
        Args:
            tx_hash: Hash of the transaction being verified
            proof: List of proof elements, each with 'position' and 'hash' fields
        
        Returns:
            bool: True if the proof is valid
        """
        if not proof:
            return self.get_root_hash() == tx_hash
        
        current_hash = tx_hash
        
        for element in proof:
            if element['position'] == 'left':
                current_hash = self.hash_pair(element['hash'], current_hash)
            else:
                current_hash = self.hash_pair(current_hash, element['hash'])
        
        return current_hash == self.get_root_hash()
    
    def serialize(self) -> Dict[str, Any]:
        """Serialize the Merkle tree structure."""
        return {
            'root_hash': self.get_root_hash(),
        }
    
    def __str__(self) -> str:
        return f"MerkleTree(root_hash={self.get_root_hash()[:8]}...)"
