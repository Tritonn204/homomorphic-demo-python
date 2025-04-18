#!/usr/bin/env python3
"""
Homomorphic Cryptography Demo
-----------------------------
This application demonstrates various homomorphic encryption schemes,
zero-knowledge proof systems, and blockchain state management.
"""

import argparse
import os
import sys

# Make sure the current directory is in the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from demos.paillier_demo import run_paillier_demo
from demos.pedersen_elgamal_demo import run_pedersen_elgamal_demo
from demos.ring_demo import run_ring_signature_demo
from demos.zk_demo import run_zk_demo
from demos.blockchain_demo import run_blockchain_demo
from demos.merkle_demo import run_merkle_demo
from utils.primes import find_working_primes_by_size

def main():
    parser = argparse.ArgumentParser(description='Homomorphic Cryptography Demos')
    parser.add_argument('--demo', type=str, 
                        choices=['paillier', 'pedersen', 'ring', 'zk', 'blockchain', 'merkle', 'primes', 'test', 'all'],
                        help='Select which demo to run', default='all')
    
    args = parser.parse_args()
    
    if args.demo == 'paillier' or args.demo == 'all':
        run_paillier_demo()
    
    if args.demo == 'pedersen' or args.demo == 'all':
        run_pedersen_elgamal_demo()
    
    if args.demo == 'ring' or args.demo == 'all':
        run_ring_signature_demo()
    
    if args.demo == 'zk' or args.demo == 'all':
        run_zk_demo()
    
    if args.demo == 'blockchain' or args.demo == 'all':
        run_blockchain_demo()
    
    if args.demo == 'merkle' or args.demo == 'all':
        run_merkle_demo()
    
    if args.demo == 'primes':
        find_working_primes_by_size()
    
    if args.demo == 'test':
        # Run the test suite
        from tests.run_tests import run_test_suite
        run_test_suite()
    
    print("\nAll demos completed.")

if __name__ == "__main__":
    main()
