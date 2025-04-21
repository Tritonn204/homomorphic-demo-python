"""
Common constants for the homomorphic encryption demo project.
All magic numbers and constants from across the codebase are centralized here.
"""

# Cryptographic constants
PEDERSEN_H_GENERATOR_SEED = b"PEDERSEN_H_GENERATOR"

# Table size constants
TABLE_MAX = 10000  # Max size for lookup tables in pedersen_elgamal.py
MAX_VALUE_RANGE = 10000  # Max range for value lookups in zk_pedersen_elgamal.py

# Transaction limits
TX_MAX_AMOUNT = 10000  # Maximum amount for transactions
TX_MIN_AMOUNT = 0      # Minimum amount for transactions (non-negative)

# Prime numbers for Paillier cryptosystem
PAILLIER_PRIME_P = 164582266122523438021796530718520447716264786386032139428492675898640548395244104114646521848386833120382750579731761970300219222952828459073248723805158721561691497204529864185193361396768084851011164401992951340942693585099212705096574206856288010548587877692918763753382364407990772475123244873470905810041
PAILLIER_PRIME_Q = 172084174117479480555949609630075409379951658357856832848305708116588064310618618361140542244767058717047624932367347152210820790338519632916344512450660693039101064646179881617199973657049854477318136730519323268184227563086883207528472644656875192552855741305729888628171268187791140343758830697165240750803

# Index values for transaction history display
TX_HISTORY_DISPLAY_COUNT = 3  # Number of recent transactions to display

# Curve names
DEFAULT_CURVE = 'secp256r1'
SMALL_CURVE = 'secp192r1'  # Smaller curve used for better performance in demos

# Account constants
DEFAULT_ACCOUNT_NAME_PREFIX = "Account-"
DEFAULT_ZK_ACCOUNT_NAME_PREFIX = "ZKAccount-"
DEFAULT_STEALTH_ACCOUNT_NAME_PREFIX = "Stealth-Account-"
RANDOM_ACCOUNT_ID_MIN = 1000
RANDOM_ACCOUNT_ID_MAX = 9999

# Key generation constants
PRIME_GEN_MIN_FACTOR = 0.75  # Lower bound factor for prime generation (75% of max)
PRIME_GEN_ATTEMPTS = 3       # Number of attempts for prime generation
PRIME_BIT_LENGTHS = [8, 16, 32, 64, 128, 256, 512, 1024] # Integer sizes (bits) to try for prime generation

# Transaction ID generation
TX_ID_LENGTH = 8  # Length of transaction ID hash prefix