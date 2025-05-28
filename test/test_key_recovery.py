import os
import gzip
import subprocess
import tempfile
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

PYTHON_EXECUTABLE = sys.executable  # Dynamically use current Python
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), '..', 'program', 'key_recovery.py')

def generate_test_file(file_path, key_bytes, n_samples=15000):
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    with gzip.open(file_path, 'wt') as f:
        for _ in range(n_samples):
            pt = get_random_bytes(16)
            ct = cipher.encrypt(pt)
            cl_values = [random.randint(50, 80) for _ in range(64)]
            for i in range(16):
                cache_set = (pt[i] ^ key_bytes[i]) % 64
                cl_values[cache_set] += random.randint(300, 400)
            cl_values = list(map(str, cl_values))
            line = f"{pt.hex()} {ct.hex()} {' '.join(cl_values)}\n"
            f.write(line)

def run_key_recovery(test_file_path):
    result = subprocess.run(
        [PYTHON_EXECUTABLE, SCRIPT_PATH, test_file_path],
        capture_output=True, text=True
    )
    print("=== STDOUT ===")
    print(result.stdout)
    print("=== STDERR ===")
    print(result.stderr)

    for line in result.stdout.splitlines():
        if "Recovered AES Key:" in line:
            return line.split(":")[-1].strip()
    raise RuntimeError("Could not extract key from output.")

def main():
    known_key_hex = "0123456789abcdeffedcba9876543210"
    key_bytes = bytes.fromhex(known_key_hex)
    with tempfile.TemporaryDirectory() as tmpdir:
        test_path = os.path.join(tmpdir, "temp_test.gz")
        generate_test_file(test_path, key_bytes)
        print(f"Running test with known key: {known_key_hex}")
        recovered_key = run_key_recovery(test_path)
        print(f"Recovered Key: {recovered_key}")
        if recovered_key.lower() == known_key_hex.lower():
            print("\nTest Passed!")
        else:
            print("\nTest Failed!")

if __name__ == "__main__":
    main()
