
from Crypto.Util import number
import hashlib
from random import random



import random



def is_prime(n, k=10):
    """Check if a number is prime using the Miller-Rabin test."""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    # Find r and d such that n-1 = 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform k iterations of the Miller-Rabin test
    for _ in range(k):
        a = random.randint(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False

    return True


def generate_primes(bit_length):
    """Generate two prime numbers of the specified bit length."""
    while True:
        # Generate two random numbers
        p = random.getrandbits(bit_length)
        q = random.getrandbits(bit_length)

        # Make sure p and q are not equal
        if p == q:
            continue

        # Test if p and q are prime
        if is_prime(p) and is_prime(q):
            return p, q
        
#for gui part
def generate_keypair(bit_length):
    p, q = generate_primes(bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = number.getRandomRange(2, phi)
    while number.GCD(e, phi) != 1:
        e = number.getRandomRange(2, phi)
    d = number.inverse(e, phi)
    return (n, e), (n, d)

def euclid_algorithm(a, b):
    """Find the greatest common divisor of a and b using Euclid's algorithm."""
    if b == 0:
        return a
    else:
        return euclid_algorithm(b, a % b)

def find_public_key(phi_n):
    """Find a value of e that is coprime to phi_n."""
    e = 2
    while euclid_algorithm(e, phi_n) != 1:
        e += 1
    return e
#d. Extended Euclid’s algorithm (EEA): to find the decryption key (d).
def extended_euclidean_algorithm(a, b):
    """Find the greatest common divisor of a and b and the coefficients x, y such that ax + by = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_euclidean_algorithm(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

def find_private_key(e, phi_n):
    """Find a value of d such that ed ≡ 1 (mod phi_n)."""
    _, d, _ = extended_euclidean_algorithm(e, phi_n)
    return d % phi_n

def hash_message(message):
    h = hashlib.sha256()
    if isinstance(message, bytes):
        message = message.decode('utf-8')
    h.update(message.encode('utf-8'))
    return h.digest()

def encrypt_message(message, public_key):
    """Encrypt a message using the RSA algorithm and a public key."""
    n, e = public_key
    message_bytes = message.encode('utf-8')
    message_int = int.from_bytes(message_bytes, byteorder='big')
    ciphertext_int = pow(message_int, e, n)
    return ciphertext_int

def decrypt_message(ciphertext, private_key):
    """Decrypt a ciphertext using the RSA algorithm and a private key."""
    n, d = private_key
    ciphertext_int = int(ciphertext)
    message_int = pow(ciphertext_int, d, n)
    message_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')
    message = message_bytes.decode('utf-8')
    return message

def generate_keypair(bit_length):
    p, q = generate_primes(bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = number.getRandomRange(2, phi)
    while number.GCD(e, phi) != 1:
        e = number.getRandomRange(2, phi)
    d = number.inverse(e, phi)
    return (n, e), (n, d)

def sha256_hash(message):
    """Compute the SHA-256 hash of a message."""
    message_bytes = message.encode('utf-8')
    hash_object = hashlib.sha256(message_bytes)
    hash_bytes = hash_object.digest()
    return hash_bytes

def sign_message(message, private_key):
    """Sign a message using RSA."""
    # Convert the message to a byte string
    message_bytes = message.encode('utf-8')
    # Compute the SHA-256 hash of the message
    message_hash = hashlib.sha256(message_bytes).digest()
    # Convert the hash to an integer
    message_int = int.from_bytes(message_hash, byteorder='big')
    # Extract the private key components
    n,d = private_key
    # Compute the signature s = m^d mod n
    signature_int = pow(message_int, d, n)
    # Convert the signature to a byte string
    signature_bytes = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, byteorder='big')
    # Convert the signature to a hex 
    signture_hex=signature_bytes.hex()
    # Return the signature
    return signture_hex

# Verify a message using RSA
def verify_signature(message, signature, public_key):
    """Verify a message using RSA."""
    # Convert the message to a byte string
    message_bytes = message.encode('utf-8')
    # Compute the SHA-256 hash of the message
    message_hash = hashlib.sha256(message_bytes).digest()
    # Convert the hash to an integer
    message_int = int.from_bytes(message_hash, byteorder='big')
    # Extract the public key components
    n,e = public_key
    # Convert the signature from hex to bytes
    signature_bytes = bytes.fromhex(signature)
    # Convert the signature to an integer
    signature_int = int.from_bytes(signature_bytes, byteorder='big')
    # Compute the message hash using the signature: m' = s^e mod n
    message_hash_int = pow(signature_int, e, n)
    # Convert the message hash to a byte string
    message_hash_bytes = message_hash_int.to_bytes((message_hash_int.bit_length() + 7) // 8, byteorder='big')
    # Verify that the computed hash matches the original hash
    return message_hash_bytes == message_hash