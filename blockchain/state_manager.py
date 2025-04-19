import time
import threading
from typing import List, Dict, Any, Optional, Callable
from .base import Blockchain, Block

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

            # Create a mining reward transaction (simplified)
            reward_tx = {
                'sender': 'COINBASE',
                'recipient': miner_address,
                'amount': 1.0,
                'timestamp': time.time()
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
    
    def start_background_scanning(self) -> None:
        """Start background thread for periodic blockchain scanning."""
        if self._scanning_thread and self._scanning_thread.is_alive():
            print("Scanner already running")
            return
        
        self._running = True
        self._scanning_thread = threading.Thread(target=self._scanning_loop)
        self._scanning_thread.daemon = True
        self._scanning_thread.start()
        print("Background scanning started")
    
    def stop_background_scanning(self) -> None:
        """Stop the background scanning thread."""
        self._running = False
        if self._scanning_thread and self._scanning_thread.is_alive():
            self._scanning_thread.join(timeout=2.0)
        print("Background scanning stopped")
    
    def _scanning_loop(self) -> None:
        """Background loop that scans blockchain periodically."""
        while self._running:
            # This is where we would implement scanning logic for waiting txs
            with self.lock:
                if self.mempool:
                    self._notify_listeners('mempool_updated', len(self.mempool))
            
            time.sleep(self.scanning_frequency)
    
    def save_state(self, filename: str) -> None:
        """Save blockchain state to file."""
        with self.lock:
            self.blockchain.save_to_file(filename)
    
    def load_state(self, filename: str) -> None:
        """Load blockchain state from file."""
        with self.lock:
            self.blockchain = Blockchain.load_from_file(filename)
            self._notify_listeners('state_loaded', len(self.blockchain.chain))
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get a summary of current blockchain state."""
        with self.lock:
            return {
                'chain_length': len(self.blockchain.chain),
                'last_block_hash': self.blockchain.get_latest_block().hash,
                'pending_transactions': len(self.blockchain.pending_transactions),
                'mempool_size': len(self.mempool),
                'difficulty': self.blockchain.difficulty
            }
