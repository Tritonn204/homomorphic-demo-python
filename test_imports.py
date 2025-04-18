#!/usr/bin/env python3

"""
Test script to verify that the import structure works correctly.
"""

import os
import sys
import time

# Add the current directory to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def test_imports():
    print("Testing import structure...")
    
    try:
        print("Importing utils...")
        from utils.primes import find_working_primes_by_size
        from utils.math_helpers import lcm, L
        print("✓ Utils imported successfully")
        
        print("Importing schemes...")
        from schemes.paillier import generate_keypair, encrypt, decrypt
        from schemes.pedersen_elgamal import PedersenElGamal, Account
        from schemes.ring_pedersen_elgamal import RingPedersenElGamal, StealthAccount
        print("✓ Schemes imported successfully")
        
        print("Importing ZKP...")
        from zkp.base import RangeProof, TransactionProof
        from zkp.zk_pedersen_elgamal import ZKPedersenElGamal, ZKAccount
        print("✓ ZKP imported successfully")
        
        print("Importing blockchain...")
        from blockchain.base import Block, Blockchain
        from blockchain.state_manager import BlockchainStateManager
        from blockchain.zk_integration import ZKTransaction, ZKBlockchainWallet
        print("✓ Blockchain imported successfully")
        
        print("Importing demos...")
        from demos.paillier_demo import run_paillier_demo
        from demos.pedersen_elgamal_demo import run_pedersen_elgamal_demo
        from demos.ring_demo import run_ring_signature_demo
        from demos.zk_demo import run_zk_demo
        from demos.blockchain_demo import run_blockchain_demo
        print("✓ Demos imported successfully")
        
        print("\nALL IMPORTS SUCCEEDED - The code structure is valid")
        return True
        
    except ImportError as e:
        print(f"\nIMPORT ERROR: {e}")
        print(f"Current path: {sys.path}")
        print("Fix the import structure and try again")
        return False
        
if __name__ == "__main__":
    if test_imports():
        print("\nWould you like to run a quick test demo? (y/n)")
        choice = input("> ").lower()
        
        if choice.startswith('y'):
            print("\nRunning Paillier demo for testing...")
            from demos.paillier_demo import run_paillier_demo
            run_paillier_demo()
            print("\nDemo complete - Structure is operational!")
