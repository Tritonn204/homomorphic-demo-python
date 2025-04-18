# Homomorphic Cryptography Demo

This repository contains a well-organized version of the homomorphic cryptography demonstration code with blockchain state management and proper Merkle tree verification. The code demonstrates various homomorphic encryption schemes, zero-knowledge proof systems, and blockchain interaction with comprehensive unit tests.

## Project Structure

The codebase has been reorganized for better separation of concerns and improved maintainability:

```
homomorphic_crypto/
│
├── utils/                   # Utility functions
│   ├── primes.py            # Prime number generation and tests
│   ├── math_helpers.py      # Common math functions
│   └── merkle.py            # Merkle tree implementation
│
├── schemes/                 # Cryptographic schemes
│   ├── paillier.py          # Paillier homomorphic encryption
│   ├── pedersen_elgamal.py  # Pedersen commitment + ElGamal encryption
│   └── ring_pedersen_elgamal.py  # Ring signature enhancements
│
├── zkp/                     # Zero-knowledge proofs
│   ├── base.py              # Base ZKP classes
│   └── zk_pedersen_elgamal.py  # ZKP with Pedersen+ElGamal
│
├── blockchain/              # Blockchain state management
│   ├── base.py              # Block and Blockchain classes
│   ├── state_manager.py     # Thread-safe blockchain state manager
│   └── zk_integration.py    # ZK integration with blockchain
│
├── demos/                   # Demonstration programs
│   ├── paillier_demo.py     # Paillier encryption demo
│   ├── pedersen_elgamal_demo.py  # Pedersen+ElGamal demo
│   ├── ring_demo.py         # Ring signature demo
│   ├── zk_demo.py           # Zero-knowledge proof demo
│   ├── blockchain_demo.py   # Blockchain with ZK transactions demo
│   └── merkle_demo.py       # Merkle tree verification demo
│
├── tests/                   # Unit tests
│   ├── test_merkle.py       # Tests for Merkle tree implementation
│   ├── test_blockchain.py   # Tests for blockchain with Merkle roots
│   └── run_tests.py         # Test runner script
│
└── main.py                  # Main entry point for all demos
```

## Installation

```bash
pip install sympy tinyec tqdm
```

## Running the Demos and Tests

You can run individual demos, all demos, or the test suite from the main program:

```bash
# Run all demos
python main.py

# Run a specific demo
python main.py --demo paillier
python main.py --demo pedersen
python main.py --demo ring
python main.py --demo zk
python main.py --demo blockchain
python main.py --demo merkle

# Run the unit tests
python main.py --demo test

# Run tests directly
cd tests
python run_tests.py

# Run the prime generation utility
python main.py --demo primes
```

## Key Components

1. **Paillier**: Implements the Paillier homomorphic encryption scheme, allowing operations on encrypted data.

2. **Pedersen+ElGamal**: Combines Pedersen commitments with twisted ElGamal encryption for value privacy with homomorphic properties.

3. **Ring Signatures**: Extends the Pedersen+ElGamal scheme with ring signatures for group anonymity.

4. **Zero-Knowledge Proofs**: Demonstrates how to prove statement validity without revealing underlying data.

5. **Blockchain Integration**: Provides blockchain state management with ZK transaction support.

## Blockchain Features

- Thread-safe state management
- Transaction scanning and validation
- Block mining with proof-of-work
- Zero-knowledge transaction support
- Event-driven architecture for updates
- Proper Merkle tree verification
- Tamper-proof transaction validation

## Testing and Verification

The codebase includes comprehensive unit tests to ensure correctness:

- **Merkle Tree Tests**: Verify tree construction, proof generation, and validation
- **Block Tests**: Verify block integrity, hash calculation, and transaction verification
- **Blockchain Tests**: Verify chain integrity, block mining, and transaction validation
- **Automated Test Runner**: Easy test execution with detailed reporting

## Benefits of the Reorganization

1. **Easier to Understand**: Logical organization of related functionality.
2. **Simpler to Extend**: Add new schemes without modifying existing code.
3. **Better Testability**: Components can be tested individually.
4. **Improved Maintainability**: Changes to one module don't affect others.
5. **Proper Separation of Concerns**: Each module handles one aspect of functionality.

## Original Code Credits

This is a reorganized version of the original homomorphic-demo-python codebase.
