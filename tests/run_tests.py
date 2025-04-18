#!/usr/bin/env python3
"""
Test runner for homomorphic cryptography project.
Runs all unit tests and reports results.
"""

import unittest
import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import test modules
from tests.test_merkle import TestMerkleTree
from tests.test_blockchain import TestBlock, TestBlockchain

def run_test_suite():
    """Run all tests and report results."""
    print("\n" + "=" * 60)
    print("  Running homomorphic cryptography test suite")
    print("=" * 60)
    
    start_time = time.time()
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestMerkleTree))
    test_suite.addTest(unittest.makeSuite(TestBlock))
    test_suite.addTest(unittest.makeSuite(TestBlockchain))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Report results
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 60)
    print(f"Test Suite completed in {elapsed_time:.3f} seconds")
    print(f"Run: {result.testsRun}, Errors: {len(result.errors)}, Failures: {len(result.failures)}")
    
    if not result.wasSuccessful():
        print("\nFailed tests:")
        for failure in result.failures:
            print(f"  - {failure[0]}")
        for error in result.errors:
            print(f"  - {error[0]} (ERROR)")
        sys.exit(1)
    else:
        print("\nAll tests passed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    run_test_suite()
