import time
import threading
import hashlib
import random
from tinyec.ec import Point
from tinyec import registry
from typing import List, Dict, Any, Optional, Callable, Union
from blockchain.base import Blockchain, Block

class BlockchainStateManager:
    """Manages blockchain state and provides thread-safe access."""
    def __init__(self):
        self.blockchain = Blockchain()
        self.lock = threading.RLock()
        self.listeners = []  # Callbacks for state changes
        self.mempool = []    # Transactions waiting to be included in blocks
        self.scanning_frequency = 10  # seconds
        self._scanning_thread = None
        self._running = False
        
        # Keep track of public keys for ring signatures
        self.public_keys_registry = []
    
    def add_transaction(self, transaction: Dict[str, Any]) -> bool:
        """Add transaction to mempool in thread-safe manner."""
        with self.lock:
            self.mempool.append(transaction)
            return True
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mine a block with transactions from mempool."""
        with self.lock:
            # Move transactions from mempool to blockchain pending
            for tx in self.mempool:
                self.blockchain.add_transaction(tx)
            self.mempool = []

            timestamp = time.time()

            # Create a mining reward transaction
            data = f"COINBASE:{miner_address}:{timestamp}"
            tx_id = hashlib.sha256(data.encode()).hexdigest()[:16]
            reward_tx = {
                'sender_address': 'COINBASE',
                'recipient_address': miner_address,
                'amount': 1,
                'timestamp': time.time(),
                'tx_id': tx_id
            }

            # Add reward transaction to list
            self.blockchain.add_transaction(reward_tx)
                
            # Mine the block
            new_block = self.blockchain.mine_pending_transactions()
            
            # Notify listeners if block was mined
            if new_block:
                self._notify_listeners('block_mined', new_block)
            
            return new_block
    
    def scan_for_address(self, address: str) -> List[Dict[str, Any]]:
        """Scan blockchain for transactions involving address."""
        with self.lock:
            return self.blockchain.scan_for_transactions(address)
    
    def add_listener(self, event_type: str, callback: Callable) -> None:
        """Add a callback function for blockchain events."""
        self.listeners.append((event_type, callback))
    
    def _notify_listeners(self, event_type: str, data: Any) -> None:
        """Notify all registered listeners of an event."""
        for listener_type, callback in self.listeners:
            if listener_type == event_type:
                callback(data)

    def get_state_summary(self) -> Dict[str, Any]:
        """Get a summary of current blockchain state."""
        with self.lock:
            last_block_hash = self.blockchain.chain[-1].hash if self.blockchain.chain[-1] else "N/A"
            
            return {
                'chain_length': len(self.blockchain.chain),
                'last_block_hash': last_block_hash,
                'pending_transactions': len(self.blockchain.pending_transactions),
                'mempool_size': len(self.mempool),
                'difficulty': self.blockchain.difficulty
            }
    
    def get_transactions_for_address(self, address: str) -> List[Dict[str, Any]]:
        """Get all transactions involving a given address."""
        all_txs = []
        
        # Look in blocks
        with self.lock:
            for block in self.blockchain.chain:
                for tx in block.transactions:
                    if isinstance(tx, dict):
                        if tx.get('sender_address') == address or tx.get('recipient_address') == address:
                            all_txs.append(tx)
                    else:
                        # Handle non-dict transactions
                        tx_dict = tx if isinstance(tx, dict) else getattr(tx, 'to_dict', lambda: {})()
                        if isinstance(tx_dict, dict):
                            if tx_dict.get('sender_address') == address or tx_dict.get('recipient_address') == address:
                                all_txs.append(tx_dict)
        
        # Also check pending transactions
        with self.lock:
            for tx in self.blockchain.pending_transactions + self.mempool:
                if isinstance(tx, dict):
                    if tx.get('sender_address') == address or tx.get('recipient_address') == address:
                        all_txs.append(tx)
                else:
                    # Handle non-dict transactions
                    tx_dict = tx if isinstance(tx, dict) else getattr(tx, 'to_dict', lambda: {})()
                    if isinstance(tx_dict, dict):
                        if tx_dict.get('sender_address') == address or tx_dict.get('recipient_address') == address:
                            all_txs.append(tx_dict)
        
        return all_txs
    
    def get_all_transactions(self) -> List[Dict[str, Any]]:
        """Get all transactions in the blockchain and mempool."""
        all_txs = []
        
        # Look in blocks
        with self.lock:
            for block in self.blockchain.chain:
                for tx in block.transactions:
                    if isinstance(tx, dict):
                        all_txs.append(tx)
                    else:
                        # Handle non-dict transactions
                        tx_dict = tx if isinstance(tx, dict) else getattr(tx, 'to_dict', lambda: {})()
                        if isinstance(tx_dict, dict):
                            all_txs.append(tx_dict)
        
        # Also check pending transactions
        with self.lock:
            for tx in self.blockchain.pending_transactions + self.mempool:
                if isinstance(tx, dict):
                    all_txs.append(tx)
                else:
                    # Handle non-dict transactions
                    tx_dict = tx if isinstance(tx, dict) else getattr(tx, 'to_dict', lambda: {})()
                    if isinstance(tx_dict, dict):
                        all_txs.append(tx_dict)
        
        return all_txs
    
    def register_public_key(self, public_key: Point) -> None:
        """Register a public key for ring signatures."""
        if public_key not in self.public_keys_registry:
            self.public_keys_registry.append(public_key)
    
    def get_random_public_keys(self, n: int, exclude: List[Point] = None, curve_name: str = 'secp192r1') -> List[Point]:
        """Get random public keys from registry or generate new ones if needed.
        Used for ring signatures to create anonymity set."""
        exclude = exclude or []
        
        # Filter out excluded keys
        available_keys = [pk for pk in self.public_keys_registry if pk not in exclude]
        
        # Generate additional keys if needed
        if len(available_keys) < n:
            curve = registry.get_curve(curve_name)
            for _ in range(n - len(available_keys)):
                # Generate a random private key
                random_priv = random.randint(1, curve.field.n - 1)
                random_pub = random_priv * curve.g
                available_keys.append(random_pub)
                self.public_keys_registry.append(random_pub)
        
        # Select random subset
        selected = random.sample(available_keys, min(n, len(available_keys)))
        
        return selected
