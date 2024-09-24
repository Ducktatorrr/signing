import os
import hmac
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES


# Utility function to convert integers to bytes
def int_to_bytes(val, length):
    return val.to_bytes(length, byteorder='little')

# Function to generate RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()
    
    # Save private key
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key

# Function to calculate modular inverse using Extended Euclidean Algorithm
def modinv(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

# Function to prepare operands and encrypt the key
def prepare_data(private_key):
    # Extract modulus (n) and private exponent (d)
    numbers = private_key.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d

    print(f"Modulus (n): {n}")
    print(f"Private Exponent (d): {d}")
    
    # Calculate Montgomery parameters
    b = 2 ** 32
    M_prime = n % b
    print(f"M_prime: {M_prime}")
    M_inv = modinv(n % b, b)
    r = (-M_inv) % b
    print(f"Montgomery parameter (r): {r}")
    
    # Convert to bytes
    Y_bytes = int_to_bytes(d, 512)  # d as 512 bytes
    M_bytes = int_to_bytes(n, 512)  # n as 512 bytes
    r_bytes = int_to_bytes(r, 512)  # r as 512 bytes
    M_prime_bytes = int_to_bytes(M_prime, 4)  # M' as 4 bytes
    
    # L calculation (for a 4096-bit key)
    L = (4096 // 32) - 1  # L = 0x7F
    L_bytes = int_to_bytes(L, 4)
    
    # Generate HMAC_KEY (256 bits)
    HMAC_KEY = os.urandom(32)
    
    # Calculate DS_KEY
    ones_256_bytes = (1 << 256) - 1
    ones_256_bytes = ones_256_bytes.to_bytes(32, byteorder='big')
    DS_KEY = hmac.new(HMAC_KEY, ones_256_bytes, sha256).digest()
    print(f"DS_KEY: {DS_KEY.hex()}")

    
    # Generate random IV (128 bits)
    IV = os.urandom(16)
    
    # Calculate MD (SHA256 hash of data)
    data_for_md = Y_bytes + M_bytes + r_bytes + M_prime_bytes + L_bytes + IV
    MD = sha256(data_for_md).digest()
    
    # Build P (Padding with PKCS#7, here using '\x08' * 8 as a fixed padding)
    beta = b'\x08' * 8
    P = Y_bytes + M_bytes + r_bytes + MD + M_prime_bytes + L_bytes + beta
    print(f"Plaintext (P): {P.hex()}")


    # Encrypt P to get ciphertext C
    cipher = AES.new(DS_KEY, AES.MODE_CBC, IV)
    C = cipher.encrypt(P)
    
    # Save C and IV to files
    with open('C.bin', 'wb') as f:
        f.write(C)
    
    with open('IV.bin', 'wb') as f:
        f.write(IV)
    
    # Save HMAC_KEY to burn into eFuse
    with open('hmac_key.bin', 'wb') as f:
        f.write(HMAC_KEY)
    
    print("Data prepared and saved. HMAC_KEY, C.bin, and IV.bin generated.")

# Main script
if __name__ == '__main__':
    private_key = generate_rsa_key()  # Step 1: Generate the RSA key pair
    prepare_data(private_key)         # Step 2: Prepare operands, encryption, and save results
    print("👴👴👴👴👴👴")