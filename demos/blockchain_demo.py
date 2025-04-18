import sys
import os
import time
import threading

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zkp.zk_pedersen_elgamal import ZKPedersenElGamal
from blockchain.state_manager import BlockchainStateManager
from blockchain.zk_integration import ZKBlockchainWallet

def run_blockchain_demo():
    print("\n==== Zero-Knowledge Blockchain Demo ====\n")
    print("Initializing blockchain with ZK transaction support...")
    
    # Create blockchain and cryptographic system
    blockchain = BlockchainStateManager()
    zk_system = ZKPedersenElGamal(curve_name='secp192r1')
    
    # Generate lookup table for fast decryption
    zk_system.generate_value_table(max_range=100)
    
    # Create wallets
    alice = ZKBlockchainWallet(zk_system, blockchain, "Alice")
    bob = ZKBlockchainWallet(zk_system, blockchain, "Bob")
    charlie = ZKBlockchainWallet(zk_system, blockchain, "Charlie")
    miner = ZKBlockchainWallet(zk_system, blockchain, "Miner")
    
    print("\nInitializing accounts with starting balances...")
    alice.account.deposit(50)
    bob.account.deposit(30)
    charlie.account.deposit(20)
    
    alice.print_status()
    bob.print_status()
    
    print("\n=== Testing Private Blockchain Transactions ===\n")
    
    print("Alice sends 15 to Bob...")
    alice.send_transaction(bob, 15)
    time.sleep(0.5)
    
    print("Bob sends 5 to Charlie...")
    bob.send_transaction(charlie, 5)
    time.sleep(0.5)
    
    print("\nTransactions are now waiting in mempool. Mining a block...")
    miner_address = f"{miner.account.pk.x}:{miner.account.pk.y}"
    block = blockchain.mine_block(miner_address)
    
    if block:
        print(f"Block mined! Hash: {block.hash[:16]}...")
        print(f"Block contains {len(block.transactions)} transactions")
    
    print("\n=== Scanning for transactions ===\n")
    print("Each account scans the blockchain for relevant transactions...")
    alice.scan_for_transactions()
    bob.scan_for_transactions()
    charlie.scan_for_transactions()
    
    print("\n=== Final Account Status ===\n")
    alice.print_status()
    bob.print_status()
    charlie.print_status()
    
    # Show blockchain state
    state = blockchain.get_state_summary()
    print("\n=== Blockchain State ===")
    print(f"Chain length: {state['chain_length']} blocks")
    print(f"Latest block: {state['last_block_hash'][:16]}...")
    print(f"Pending transactions: {state['pending_transactions']}")
    print(f"Mempool size: {state['mempool_size']}")
    print(f"Mining difficulty: {state['difficulty']}")
    
    print("\n==== End of Blockchain Demo ====")

if __name__ == "__main__":
    run_blockchain_demo()
