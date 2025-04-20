import time
import hashlib
import json
from typing import Dict, Any, List, Optional

from .base import Blockchain
from .state_manager import BlockchainStateManager
import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zkp.zk_pedersen_elgamal import ZKPedersenElGamal, ZKAccount, ZKPoint
from tinyec import registry
from tinyec.ec import Point

from utils.math_helpers import safe_equals

def reconstruct_ciphertext_from_dict(data, curve_name='secp192r1'):
    curve = registry.get_curve(curve_name)
    c1 = Point(curve, data['ciphertext_c1_x'], data['ciphertext_c1_y'])
    c2 = Point(curve, data['ciphertext_c2_x'], data['ciphertext_c2_y'])
    return (c1, c2)

class ZKTransaction:
    """A zero-knowledge transaction that can be added to the blockchain."""
    def __init__(self, sender_pk, recipient_pk, ciphertext, amount_proof, balance_proof, signature, sender_address=None, recipient_address=None):
        self.sender_pk = sender_pk
        self.recipient_pk = recipient_pk
        self.ciphertext = ciphertext
        self.amount_proof = amount_proof
        self.balance_proof = balance_proof
        self.signature = signature
        self.timestamp = time.time()
        self.sender_address = sender_address or f"{self.sender_pk.x}:{self.sender_pk.y}"
        self.recipient_address = recipient_address or f"{self.recipient_pk.x}:{self.recipient_pk.y}"
        self.tx_id = self._generate_tx_id()
    
    def _generate_tx_id(self) -> str:
        """Generate a unique transaction ID."""
        # In a real system, this would use more sophisticated ID generation
        data = f"{self.sender_address}:{self.recipient_address}:{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to serializable dict for blockchain storage."""
        c1, c2 = self.ciphertext
        return {
            'tx_id': self.tx_id,
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'ciphertext_c1_x': c1.x,
            'ciphertext_c1_y': c1.y,
            'ciphertext_c2_x': c2.x,
            'ciphertext_c2_y': c2.y,
            'amount_proof': self.amount_proof,
            'balance_proof': self.balance_proof,
            'signature': self.signature,
            'timestamp': self.timestamp
        }
    
    @staticmethod
    def verify_transaction(tx_dict: Dict[str, Any], zk_system: ZKPedersenElGamal) -> bool:
        """Verify transaction validity without knowing the amount."""
        if tx_dict.get("sender_address") == "COINBASE":
            return True

        return zk_system.verify_zk_transaction(tx_dict)


class ZKBlockchainWallet:
    """Wallet that interacts with blockchain using zero-knowledge proofs."""
    def __init__(self, zk_system: ZKPedersenElGamal, blockchain: BlockchainStateManager, name: Optional[str] = None):
        self.zk_system = zk_system
        self.blockchain = blockchain
        self.account = ZKAccount(zk_system, name)
        self.scanning_interval = 5  # seconds
        self.address = f"{self.account.pk.x}:{self.account.pk.y}"
        self.spent_nullifiers = set()
        
        # Register for blockchain events
        self.blockchain.add_listener('block_mined', self._on_block_mined)
    
    def send_transaction(self, recipient, amount: float) -> bool:
        """Send private transaction to recipient via blockchain."""
        if amount > self.get_balance():
            print(f"Insufficient balance: {self.get_balance()} < {amount}")
            return False
        
        # Create private transaction with ZK proof
        tx = self.zk_system.create_zk_transaction(
            self.account.sk, self.account.pk, recipient.account.pk, amount, self.account.balance
        )
        
        # Convert to blockchain-compatible format
        zk_tx = ZKTransaction(
            self.account.pk, recipient.account.pk,
            tx['ciphertext'], tx['amount_proof'], tx['balance_proof'], tx['signature'],
            sender_address=self.address, recipient_address=recipient.address
        )
        
        if not self.zk_system.verify_zk_transaction(zk_tx.to_dict()):
            return False

        # Add to blockchain
        self.blockchain.add_transaction(zk_tx.to_dict())
        
        # Update local state
        self.account.balance -= amount
        self.account.transactions.append({
            'type': 'send',
            'recipient': recipient.account.name,
            'recipient_address': recipient.address, 
            'amount': amount,
            'tx_id': zk_tx.tx_id,
            'timestamp': time.time()
        })
        
        print(f"{self.account.name} sent {amount} to {recipient.account.name} (TX ID: {zk_tx.tx_id})")
        return True
    
    def scan_for_transactions(self) -> None:
        """Scan blockchain for incoming transactions."""
        # Use the full wallet address for scanning
        transactions = self.blockchain.scan_for_address(self.address)
        
        for tx_info in transactions:
            tx = tx_info['transaction']

            # Skip already processed transactions
            if tx.get('tx_id') in self.spent_nullifiers:
                continue
            
            # Check if this transaction is for us using the wallet address
            if tx.get('recipient_address') == self.address:
                if not tx.get("sender_address") == "COINBASE":
                    if not self.zk_system.verify_zk_transaction(tx):
                        continue

                if tx.get('amount') != None:
                    amount = tx.get('amount')
                else:
                    ciphertext = reconstruct_ciphertext_from_dict(tx)
                    amount = self.zk_system.constant_time_decrypt(
                      ciphertext, 
                      self.account.sk,
                      None
                    )

                # Update local state with more data
                sender_display = tx.get('sender_address', '').split(':')[0][:8]
                self.account.balance += amount
                self.account.transactions.append({
                    'type': 'receive',
                    'sender': sender_display,
                    'sender_address': tx.get('sender_address'),
                    'amount': amount,
                    'tx_id': tx.get('tx_id'),
                    'timestamp': tx.get('timestamp', time.time())
                })
                
                # Mark as processed
                self.spent_nullifiers.add(tx.get('tx_id'))
                
                print(f"{self.account.name} received {amount} (TX ID: {tx.get('tx_id')})")
    
    def get_balance(self) -> float:
        """Get wallet balance."""
        return self.account.balance
    
    def print_status(self) -> None:
        """Print wallet status."""
        self.account.print_status()
        print(f"Blockchain Address: {self.address[:16]}...")
        print(f"Processed Transactions: {len(self.spent_nullifiers)}\n")
    
    def _on_block_mined(self, block) -> None:
        """Handle new block event."""
        self.scan_for_transactions()
