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

# Import the live console
from live_console import run_blockchain_console

try:
    # Try importing from the original demos
    from demos.paillier_demo import run_paillier_demo
    from demos.pedersen_elgamal_demo import run_pedersen_elgamal_demo
    from demos.ring_demo import run_ring_signature_demo
    from demos.zk_demo import run_zk_demo
    
    # Import newer demos
    try:
        from demos.blockchain_demo import run_blockchain_demo
        BLOCKCHAIN_DEMO_AVAILABLE = True
    except ImportError:
        BLOCKCHAIN_DEMO_AVAILABLE = False
        
    try:
        from demos.merkle_demo import run_merkle_demo
        MERKLE_DEMO_AVAILABLE = True
    except ImportError:
        MERKLE_DEMO_AVAILABLE = False
        
    from utils.primes import find_working_primes_by_size
except ImportError:
    print("Warning: Some demo modules could not be imported. Using fixed console only.")
    BLOCKCHAIN_DEMO_AVAILABLE = False
    MERKLE_DEMO_AVAILABLE = False

def main():
    parser = argparse.ArgumentParser(description='Homomorphic Cryptography Demos')
    parser.add_argument('--demo', type=str, 
                        choices=['paillier', 'pedersen', 'ring', 'zk', 'blockchain', 'merkle', 
                                'primes', 'test', 'live', 'all'],
                        help='Select which demo to run', default='all')
    parser.add_argument('--scheme', type=str,
                        choices=['zk-pedersen-elgamal', 'ring-pedersen-elgamal'],
                        help='Select encryption scheme for live demo', default='zk-pedersen-elgamal')
    
    args = parser.parse_args()
    
    if args.demo == 'live':
        print(f"\n=== Starting Interactive Blockchain Console with {args.scheme} protection ===")
        run_blockchain_console(args.scheme)
        return

    # Run the requested demo(s)
    if args.demo == 'paillier' or args.demo == 'all':
        try:
            run_paillier_demo()
        except Exception as e:
            print(f"Error in Paillier demo: {e}")
    
    if args.demo == 'pedersen' or args.demo == 'all':
        try:
            run_pedersen_elgamal_demo()
        except Exception as e:
            print(f"Error in Pedersen demo: {e}")
    
    if args.demo == 'ring' or args.demo == 'all':
        try:
            run_ring_signature_demo()
        except Exception as e:
            print(f"Error in Ring Signature demo: {e}")
    
    if args.demo == 'zk' or args.demo == 'all':
        try:
            run_zk_demo()
        except Exception as e:
            print(f"Error in ZK demo: {e}")
    
    if (args.demo == 'blockchain' or args.demo == 'all') and BLOCKCHAIN_DEMO_AVAILABLE:
        try:
            run_blockchain_demo()
        except Exception as e:
            print(f"Error in Blockchain demo: {e}")
    
    if (args.demo == 'merkle' or args.demo == 'all') and MERKLE_DEMO_AVAILABLE:
        try:
            run_merkle_demo()
        except Exception as e:
            print(f"Error in Merkle demo: {e}")
    
    if args.demo == 'primes':
        try:
            find_working_primes_by_size()
        except Exception as e:
            print(f"Error finding primes: {e}")
    
    if args.demo == 'test':
        # Run the test suite (if available)
        try:
            from tests.run_tests import run_test_suite
            run_test_suite()
        except ImportError:
            print("Test suite not available")
    
    
    print("\nAll demos completed.")

if __name__ == "__main__":
    main()