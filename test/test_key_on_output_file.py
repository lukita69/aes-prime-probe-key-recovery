from Crypto.Cipher import AES
from binascii import unhexlify
import gzip

# Define the recovered key
key_hex = "A965F96D2029FE5A2232A87DEF7D3C7A"
key_bytes = bytes.fromhex(key_hex)

# Set up AES cipher
cipher = AES.new(key_bytes, AES.MODE_ECB)

# Open and read output.txt (gzip if needed)
path = "../data/output.txt.gz"
with gzip.open(path, 'rt') as f:
    lines = [next(f) for _ in range(50)]  # Check first 5 lines

# Compare ciphertexts
for line in lines:
    parts = line.strip().split()
    if len(parts) < 2:
        continue
    plaintext = bytes.fromhex(parts[0])
    expected_ciphertext = parts[1]
    computed_ciphertext = cipher.encrypt(plaintext).hex()

    print(f"Plaintext:           {parts[0]}")
    print(f"Expected Ciphertext: {expected_ciphertext}")
    print(f"Computed Ciphertext: {computed_ciphertext}")
    print(f"Match:               {expected_ciphertext == computed_ciphertext}")
    print("-" * 60)
