#!/usr/bin/env python3
"""
Live Blockchain Console
----------------------------
An interactive console for running a blockchain with proper homomorphic encryption
and zero-knowledge proofs to prevent negative balances and properly validate transactions.
"""

import argparse
import os
import sys
import threading
import time
import cmd
import json
import hashlib
from typing import Optional, Dict, Any, List, Tuple, Union

# Make sure the codebase is in the path
sys.path.insert(0, os.path.abspath("/tmp/inputs/homomorphic-demo-python"))

# Import the available schemes and their integrations
from zkp.zk_pedersen_elgamal import ZKPedersenElGamal
from schemes.ring_pedersen_elgamal import RingPedersenElGamal
from zkp.base import RangeProof
from blockchain.state_manager import BlockchainStateManager
from blockchain.zk_integration import ZKBlockchainWallet, ZKTransaction
from blockchain.ring_integration import RingBlockchainWallet, RingTransaction


class InteractiveBlockchainConsole(cmd.Cmd):
    """Interactive console for blockchain operations with ZK protections."""
    
    intro = """
    =========================================================
    Homomorphic Encryption Blockchain Interactive Console
    =========================================================
    Type 'help' for available commands
    Type 'exit' or 'quit' to exit the console
    Type 'mine' to mine the next block with pending transactions
    """
    prompt = "blockchain> "
    
    def __init__(self, encryption_scheme: str = "zk-pedersen-elgamal"):
        super().__init__()
        self.encryption_scheme = encryption_scheme
        self.init_blockchain()
    
    def init_blockchain(self):
        """Initialize blockchain with proper setup for selected scheme."""
        print(f"\nInitializing blockchain with {self.encryption_scheme} encryption scheme...")
        
        # Initialize the appropriate cryptographic system based on scheme
        if self.encryption_scheme == "zk-pedersen-elgamal":
            try:
                self.crypto_system = ZKPedersenElGamal(curve_name='secp192r1')
                
                # Generate lookup table for constant-time decryption
                print("Generating elgamal value table for transaction verification...")
                self.crypto_system.generate_value_table(max_range=10000)
                
                # Initialize blockchain state manager
                self.state_manager = BlockchainStateManager()
                
                # Setup default wallets with initial balances
                self.setup_default_wallets_zk()
                
                print(f"✓ Blockchain initialized with {self.encryption_scheme} encryption")
            except Exception as e:
                print(f"Error initializing blockchain: {str(e)}")
                sys.exit(1)
                
        elif self.encryption_scheme == "ring-pedersen-elgamal":
            try:
                print("Generating elgamal value table for transaction verification...")
                self.crypto_system = RingPedersenElGamal(curve_name='secp192r1')
                
                # Initialize blockchain state manager
                self.state_manager = BlockchainStateManager()
                
                # Setup default wallets with initial balances
                self.setup_default_wallets_ring()
                
                print(f"✓ Blockchain initialized with {self.encryption_scheme} encryption")
            except Exception as e:
                print(f"Error initializing blockchain: {str(e)}")
                sys.exit(1)
        else:
            print(f"Unsupported encryption scheme: {self.encryption_scheme}")
            sys.exit(1)
    
    def setup_default_wallets_zk(self):
        """Create default wallets with ZK handling."""
        # Create miner wallet with proper ZK handling
        self.miner_wallet = ZKBlockchainWallet(self.crypto_system, self.state_manager, "Miner")
        self.miner_address = self.miner_wallet.address
        
        # Create some user wallets for demonstration
        self.alice = ZKBlockchainWallet(self.crypto_system, self.state_manager, "Alice")
        self.bob = ZKBlockchainWallet(self.crypto_system, self.state_manager, "Bob")
        self.charlie = ZKBlockchainWallet(self.crypto_system, self.state_manager, "Charlie")
        
        # Initialize with some balance using blockchain's deposit method
        print("\nFunding initial wallets...")
        self.alice.account.deposit(50)
        self.bob.account.deposit(30)
        self.charlie.account.deposit(20)
        
        print("Initial wallet status:")
        self.alice.print_status()
        self.bob.print_status()
    
    def setup_default_wallets_ring(self):
        """Create default wallets with Ring signature handling."""
        # Create miner wallet with Ring signature handling
        self.miner_wallet = RingBlockchainWallet(self.crypto_system, self.state_manager, "Miner")
        self.miner_address = self.miner_wallet.address
        
        # Create some user wallets for demonstration
        self.alice = RingBlockchainWallet(self.crypto_system, self.state_manager, "Alice")
        self.bob = RingBlockchainWallet(self.crypto_system, self.state_manager, "Bob")
        self.charlie = RingBlockchainWallet(self.crypto_system, self.state_manager, "Charlie")
        
        # Initialize with some balance
        print("\nFunding initial wallets...")
        self.alice.deposit(50)
        self.bob.deposit(30)
        self.charlie.deposit(20)
        
        print("Initial wallet status:")
        self.alice.print_status()
        self.bob.print_status()
    
    def _verify_transaction_validity(self, sender_wallet, amount: int) -> bool:
        """Verify if a transaction is valid using appropriate method."""
        if self.encryption_scheme == "zk-pedersen-elgamal":
            # Use ZK range proofs for verification
            current_balance = sender_wallet.get_balance()
            
            try:
                amount_proof = RangeProof(amount, min_value=0, max_value=current_balance)
                if not amount_proof.verify():
                    print("ZK Proof Failed: Amount range verification failed")
                    return False
            except ValueError as e:
                print(f"ZK Proof Failed: {str(e)}")
                return False
            
            if amount > current_balance:
                print(f"ZK Proof Failed: Insufficient funds ({current_balance} < {amount})")
                return False
            
            return True
            
        elif self.encryption_scheme == "ring-pedersen-elgamal":
            # For Ring signature, we just check the basic balance
            current_balance = sender_wallet.get_balance()
            
            if amount <= 0:
                print("Transaction Failed: Amount must be positive")
                return False
            
            if amount > current_balance:
                print(f"Transaction Failed: Insufficient funds ({current_balance} < {amount})")
                return False
            
            return True
        
        raise Exception(f"Unknown encryption scheme: {self.encryption_scheme}")

    def do_mine(self, arg):
        """Mine a new block with pending transactions."""
        print("\nMining new block...")
        
        # Use the miner wallet for rewards
        miner_address = self.miner_address
        
        # Mine the block
        block = self.state_manager.mine_block(miner_address)
        
        if block:
            self.print_block_summary(block)
        else:
            print("No transactions to mine.")
    
    def do_status(self, arg):
        """Display the current blockchain status."""
        state = self.state_manager.get_state_summary()
        print("\n=== Blockchain Status ===")
        print(f"Chain length: {state['chain_length']} blocks")
        print(f"Latest block hash: {state['last_block_hash'][:16]}...")
        print(f"Pending transactions: {state['pending_transactions']}")
        print(f"Mempool size: {state['mempool_size']}")
        print(f"Mining difficulty: {state['difficulty']}")
        print(f"Encryption scheme: {self.encryption_scheme}")
    
    def do_wallet_status(self, arg):
        """Display status of a specific wallet by name."""
        if not arg:
            print("Usage: wallet_status <wallet_name>")
            return
        
        wallet_name = arg.strip()
        
        # Lookup wallet by name
        if wallet_name.lower() == "alice":
            self.alice.print_status()
        elif wallet_name.lower() == "bob":
            self.bob.print_status()
        elif wallet_name.lower() == "charlie":
            self.charlie.print_status()
        elif wallet_name.lower() == "miner":
            self.miner_wallet.print_status()
        else:
            print(f"Unknown wallet: {wallet_name}")
    
    def do_list_wallets(self, arg):
        # Only visible because this demo simulates having access to all private keys
        """List all available wallets with current balances."""
        print("\n=== Available Wallets ===")
        print(f"1. Alice    - Address: {self.alice.address[:16]}... - Balance: {self.alice.get_balance():.2f}")
        print(f"2. Bob      - Address: {self.bob.address[:16]}... - Balance: {self.bob.get_balance():.2f}")
        print(f"3. Charlie  - Address: {self.charlie.address[:16]}... - Balance: {self.charlie.get_balance():.2f}")
        print(f"4. Miner    - Address: {self.miner_wallet.address[:16]}... - Balance: {self.miner_wallet.get_balance():.2f}")
    
    def do_send(self, arg):
        """Send funds from one wallet to another with verification.
        Usage: send <sender_name> <recipient_name> <amount>
        Example: send alice bob 15.5"""
        args = arg.split()
        
        if len(args) != 3:
            print("Usage: send <sender_name> <recipient_name> <amount>")
            return
        
        sender_name, recipient_name, amount_str = args
        
        # Convert amount to float with validation
        try:
            amount = int(amount_str)
            if amount <= 0:
                print("Amount must be positive")
                return
        except ValueError:
            print("Amount must be a number")
            return
        
        # Get sender and recipient wallets
        sender_wallet = self._get_wallet_by_name(sender_name)
        recipient_wallet = self._get_wallet_by_name(recipient_name)
        
        if not sender_wallet or not recipient_wallet:
            print("Error: Invalid sender or recipient wallet name")
            return
        
        # Verify transaction with appropriate method
        if not self._verify_transaction_validity(sender_wallet, amount):
            return
        
        # Execute transaction
        print(f"\nSending {amount} from {sender_name} to {recipient_name}...")
        result = sender_wallet.send_transaction(recipient_wallet, amount)
        
        if result:
            print(f"Transaction successful!")
        else:
            print("Transaction failed")
    
    def do_show_block(self, arg):
        """Show details of a mined block. Usage: show_block [block_index]"""
        if not arg:
            print("No block index specified")
            return
        
        try:
            block_index = int(arg)

            if block_index >= len(self.state_manager.blockchain.chain):
                print("Block index out of range")
                return

            print(f"Block #{block_index}\n{self.state_manager.blockchain.chain[block_index].to_dict()}")
        except ValueError:
            print("Block index must be a number")
    
    def print_block_summary(self, block):
        """Print a summary of a mined block."""
        print("\n=== New Block Mined ===")
        if hasattr(block, 'index'):
            print(f"Index: {block.index}")
            print(f"Hash: {block.hash[:16]}...")
            print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}")
            print(f"Transactions: {len(block.transactions)}")
            print(f"Previous Hash: {block.previous_hash[:16]}...")
        else:
            print(f"Block summary: {block}")
    
    def _get_wallet_by_name(self, name: str) -> Optional[Union[ZKBlockchainWallet, RingBlockchainWallet]]:
        """Get wallet by name."""
        name = name.lower()
        if name == "alice":
            return self.alice
        elif name == "bob":
            return self.bob
        elif name == "charlie":
            return self.charlie
        elif name == "miner":
            return self.miner_wallet
        return None
    
    def do_quit(self, arg):
        """Exit the blockchain console."""
        print("Exiting blockchain console...")
        return True
    
    def do_exit(self, arg):
        """Exit the blockchain console."""
        return self.do_quit(arg)
    
    def do_help(self, arg):
        """List available commands."""
        commands = [
            ("mine", "Mine a new block with pending transactions"),
            ("status", "Display the current blockchain status"),
            ("wallet_status <name>", "Display status of a specific wallet"),
            ("list_wallets", "List all available wallets"),
            ("send <sender> <recipient> <amount>", "Send funds between wallets"),
            ("show_block <block_index>", "Show details of a mined block"),
            ("help", "List available commands"),
            ("exit/quit", "Exit the blockchain console")
        ]
        
        print("\nAvailable Commands:")
        for cmd, desc in commands:
            print(f" {cmd:<25} {desc}")
        print()


def run_blockchain_console(encryption_scheme="zk-pedersen-elgamal"):
    """Start the live blockchain console with proper integration."""
    print(f"\n==== Starting Live Blockchain Console with {encryption_scheme} ====\n")
    console = InteractiveBlockchainConsole(encryption_scheme)
    console.cmdloop()
    print("\n==== Exiting Live Blockchain Console ====")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Live Blockchain Console with ZK or Ring Proofs')
    parser.add_argument('--scheme', type=str, 
                        choices=['zk-pedersen-elgamal', 'ring-pedersen-elgamal'],
                        help='Select encryption scheme', default='zk-pedersen-elgamal')
    
    args = parser.parse_args()
    run_blockchain_console(args.scheme)