import random
from math import gcd

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def generate_keypair(p, q):
    n = p * q
    g = n + 1
    lambda_ = lcm(p - 1, q - 1)
    mu = pow(lambda_, -1, n)
    return ((n, g), (lambda_, mu))

def L(x, n):
    return (x - 1) // n

def encrypt(pub_key, m):
    n, g = pub_key
    r = random.randint(1, n - 1)
    return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

def decrypt(pub_key, priv_key, c):
    n, _ = pub_key
    lambda_, mu = priv_key
    return (L(pow(c, lambda_, n * n), n) * mu) % n

def add_encrypted(pub_key, c1, c2):
    n, _ = pub_key
    return (c1 * c2) % (n * n)

# Example usage
p = 164582266122523438021796530718520447716264786386032139428492675898640548395244104114646521848386833120382750579731761970300219222952828459073248723805158721561691497204529864185193361396768084851011164401992951340942693585099212705096574206856288010548587877692918763753382364407990772475123244873470905810041
q = 172084174117479480555949609630075409379951658357856832848305708116588064310618618361140542244767058717047624932367347152210820790338519632916344512450660693039101064646179881617199973657049854477318136730519323268184227563086883207528472644656875192552855741305729888628171268187791140343758830697165240750803
pub_key, priv_key = generate_keypair(p, q)

# Test cases
test_cases = [
    (5, 3),
    (10, 20),
    (100, 200),
    (1000, 2000),
    (12345, 67890),
    (1000000, 2000000),
    (0, 100),
    (999, 1),
    (54321, 12345),
    (7, 7)
]

def run_test_case(m1, m2):
    c1 = encrypt(pub_key, m1)
    c2 = encrypt(pub_key, m2)
    c_sum = add_encrypted(pub_key, c1, c2)
    decrypted_sum = decrypt(pub_key, priv_key, c_sum)
    print(f"Test case: {m1} + {m2}")
    # print(f"Encrypted values: c1 = {c1}, c2 = {c2}")
    # print(f"Encrypted sum: {c_sum}")
    # print(f"Decrypted sum: {decrypted_sum}")
    print(f"Actual sum: {m1 + m2}")
    print(f"{'Passed' if decrypted_sum == m1 + m2 else 'Failed'}\n")

# Run test cases
for m1, m2 in test_cases:
    run_test_case(m1, m2)