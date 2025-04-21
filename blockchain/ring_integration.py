import time
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple

from blockchain.base import Blockchain
from blockchain.state_manager import BlockchainStateManager
import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.ring_pedersen_elgamal import RingPedersenElGamal, StealthAccount
from tinyec import registry
from tinyec.ec import Point

from utils.math_helpers import safe_equals

def reconstruct_ciphertext_from_dict(data, curve):
    c1 = Point(curve, data['ciphertext_c1_x'], data['ciphertext_c1_y'])
    c2 = Point(curve, data['ciphertext_c2_x'], data['ciphertext_c2_y'])
    return (c1, c2)

def point_to_dict(point: Point) -> Dict[str, int]:
    """Convert EC point to dictionary representation."""
    return {'x': point.x, 'y': point.y}

def dict_to_point(point_dict: Dict[str, int], curve) -> Point:
    """Convert dictionary representation to EC point."""
    return Point(curve, point_dict['x'], point_dict['y'])

class RingTransaction:
    """A ring signature transaction with stealth addressing."""
    def __init__(self, sender_pk, stealth_address, ciphertext, ring_signature, public_keys, 
                 sender_address=None, recipient_address=None):
        self.sender_pk = sender_pk
        self.stealth_R, self.stealth_P = stealth_address  # R and P values for stealth address
        self.ciphertext = ciphertext
        self.ring_signature = ring_signature
        self.public_keys = public_keys
        self.timestamp = time.time()
        self.sender_address = sender_address or f"{self.sender_pk.x}:{self.sender_pk.y}"
        self.recipient_address = recipient_address or f"stealth:{self.stealth_P.x}:{self.stealth_P.y}"
        self.tx_id = self._generate_tx_id()
    
    def _generate_tx_id(self) -> str:
        """Generate a unique transaction ID."""
        data = f"{self.sender_address}:{self.recipient_address}:{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to serializable dict for blockchain storage."""
        c1, c2 = self.ciphertext
        return {
            'tx_id': self.tx_id,
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'stealth_R': point_to_dict(self.stealth_R),
            'stealth_P': point_to_dict(self.stealth_P),
            'ciphertext_c1_x': c1.x,
            'ciphertext_c1_y': c1.y,
            'ciphertext_c2_x': c2.x,
            'ciphertext_c2_y': c2.y,
            'ring_signature': self.ring_signature,
            'public_keys': [point_to_dict(pk) for pk in self.public_keys],
            'timestamp': self.timestamp
        }
    
    @staticmethod
    def verify_transaction(tx_dict: Dict[str, Any], ring_system: RingPedersenElGamal) -> bool:
        """Verify transaction validity using ring signature."""
        if tx_dict.get("sender_address") == "COINBASE":
            return True

        try:
            # Reconstruct public keys from dict
            curve = registry.get_curve(ring_system.curve)
            public_keys = [dict_to_point(pk_dict, ring_system.curve) 
                          for pk_dict in tx_dict['public_keys']]
            
            # Reconstruct ciphertext
            ciphertext = reconstruct_ciphertext_from_dict(tx_dict, ring_system.curve)
            
            # Generate message for signature verification
            message = f"{tx_dict['sender_address']}:{tx_dict['recipient_address']}:{tx_dict['timestamp']}"
            
            # Verify the ring signature
            return ring_system.verify_ring_signature(message, public_keys, tx_dict['ring_signature'])
        except Exception as e:
            print(f"Error verifying transaction: {str(e)}")
            return False

class RingBlockchainWallet:
    """Wallet for blockchain transactions using Ring Pedersen ElGamal with stealth addresses."""
    def __init__(self, ring_system, state_manager, name=None):
        self.ring_system = ring_system
        self.state_manager = state_manager
        self.name = name or f"User-{hash(time.time())}"
        self.account = StealthAccount(ring_system, name)
        
        # Get view and spend public keys
        self.view_pk, self.spend_pk = self.account.get_public_address()
        self.public_key = self.spend_pk  # For compatibility
        
        self.transactions = []
        self.spent_nullifiers = set()

        # Register for blockchain events
        self.state_manager.add_listener('block_mined', self._on_block_mined)

        # Format address to include both view and spend keys
        self.address = f"ring:{self.view_pk.x}:{self.view_pk.y}:{self.spend_pk.x}:{self.spend_pk.y}"
    
    def send_transaction(self, recipient_wallet, amount: int) -> bool:
        """Send funds to another wallet using Ring Pedersen ElGamal with stealth addressing."""
        if amount <= 0:
            print("Amount must be positive")
            return False
        
        if amount > self.get_balance():
            print(f"Insufficient funds: {self.get_balance()} < {amount}")
            return False
        
        # Get recipient's view and spend public keys
        recipient_view_pk, recipient_spend_pk = recipient_wallet.account.get_public_address()
        
        # Generate one-time stealth address for recipient
        stealth_address = self.ring_system.generate_stealth_address(recipient_view_pk, recipient_spend_pk)
        R, P = stealth_address
        
        # Encrypt transaction amount using recipient's public key
        plaintext = amount
        ciphertext = self.ring_system.twisted_elgamal_encrypt(plaintext, recipient_view_pk)
        
        # Create a message for signing
        message = f"{self.address}:stealth:{P.x}:{P.y}:{time.time()}"
        
        # Obtain some extra public keys for the ring (in a real scenario these would be from the network)
        public_keys = self.state_manager.get_random_public_keys(3, exclude=[self.spend_pk])
        public_keys.append(self.spend_pk)
        
        # Sign with ring signature
        signer_idx = len(public_keys) - 1  # Our key is the last one
        ring_signature = self.ring_system.generate_ring_signature(message, signer_idx, public_keys, 
                                                                self.account.spend_sk)
        
        # Create transaction
        transaction = RingTransaction(
            sender_pk=self.spend_pk,
            stealth_address=(R, P),
            ciphertext=ciphertext,
            ring_signature=ring_signature,
            public_keys=public_keys,
            sender_address=self.address,
            recipient_address=f"stealth:{P.x}:{P.y}"
        )
        
        # Submit to blockchain
        result = self.state_manager.add_transaction(transaction.to_dict())
        
        if result:
            self.account.balance -= amount
            self.transactions.append(transaction)
            print(f"{self.name} sent {amount} coins via stealth address")
        
        return result
    
    def get_balance(self) -> int:
        """Get current wallet balance."""
        return self.account.balance
    
    def deposit(self, amount: int) -> bool:
        """Deposit funds directly into account (used for testing)."""
        if amount <= 0:
            print("Deposit amount must be positive")
            return False
        
        self.account.balance += amount
        return True
    
    def scan_for_transactions(self):
        """Scan blockchain for transactions involving this wallet."""        
        # Also scan for stealth transactions directed to us
        all_transactions = self.state_manager.get_all_transactions()
        
        for tx in all_transactions:
            is_coinbase = tx.get('sender_address') == 'COINBASE' and tx.get('recipient_address') == self.address

            # Skip non-stealth or already processed transactions
            if not tx.get('recipient_address', '').startswith('stealth:') and not is_coinbase:
                continue
                
            if tx.get('tx_id') in self.spent_nullifiers:
                continue

            # Get stealth address components
            try:
                if not is_coinbase:                
                    R = dict_to_point(tx['stealth_R'], self.ring_system.curve)
                    P = dict_to_point(tx['stealth_P'], self.ring_system.curve)
                else:
                    R = None
                    P = None
                
                # Check if this stealth transaction belongs to us
                if is_coinbase or self.ring_system.recover_stealth_address(R, P, self.account.view_sk, self.spend_pk):
                    # Found a stealth transaction for us! Decrypt it
                    if tx.get('amount') != None:
                        amount = tx.get('amount')
                    else:
                        ciphertext = reconstruct_ciphertext_from_dict(tx, self.ring_system.curve)
                        amount = self.ring_system.twisted_elgamal_decrypt(ciphertext, self.account.view_sk)

                    # Update account
                    self.account.balance += amount
                    self.account.received_funds.append((amount, R, P))
    
                    self.transactions.append({
                        'type': 'receive',
                        'sender_address': tx.get('sender_address'),
                        'amount': amount,
                        'tx_id': tx.get('tx_id'),
                        'timestamp': tx.get('timestamp', time.time())
                    })
                    print(f"{self.name} received {amount} coins via stealth address")

                    self.spent_nullifiers.add(tx.get('tx_id'))

            except Exception as e:
                print(f"Failed to process TX {tx['tx_id']}: {e}")
                continue
    
    def print_status(self):
        """Print wallet status."""
        print(f"\n=== {self.name} Wallet Status ===")
        print(f"Address: {self.address[:32]}...")
        print(f"Balance: {self.get_balance()}")
        print(f"View Public Key: ({self.view_pk.x}, {self.view_pk.y})")
        print(f"Spend Public Key: ({self.spend_pk.x}, {self.spend_pk.y})")
        print(f"Transactions: {len(self.transactions)}")
        print(f"Received via stealth: {len(self.account.received_funds)}")
        
        # Show recent transactions
        if self.transactions:
            print("\nRecent Transactions:")
            for i, tx in enumerate(self.transactions[-5:]):
                tx_dict = tx.to_dict() if hasattr(tx, 'to_dict') else tx
                if isinstance(tx_dict, dict):
                    if tx_dict.get('sender_address') == self.address:
                        print(f"  {i+1}. SENT: {tx_dict.get('tx_id', '????')} via stealth address")
                    elif tx_dict.get('recipient_address', '').startswith('stealth:'):
                        print(f"  {i+1}. RECEIVED: {tx_dict.get('tx_id', '????')} via stealth address")
                    else:
                        print(f"  {i+1}. INVOLVED: {tx_dict.get('tx_id', '????')}")
        print()

    def _on_block_mined(self, block) -> None:
        """Handle new block event."""
        self.scan_for_transactions()
