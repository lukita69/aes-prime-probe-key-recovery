import subprocess
import os
import gzip
import shutil

# Paths
PROGRAM_DIR = os.path.join(os.path.dirname(__file__), '..', 'program')
TEST_INPUT_GZ = os.path.join(os.path.dirname(__file__), 'test_input.txt.gz')
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
TEMP_INPUT_TXT = os.path.join(DATA_DIR, 'output.txt')
EXPECTED_KEY_PATH = os.path.join(os.path.dirname(__file__), 'expected_key.txt')
SCRIPT_PATH = os.path.join(PROGRAM_DIR, 'key_recovery.py')

# Extract the test file
with gzip.open(TEST_INPUT_GZ, 'rt') as fin, open(TEMP_INPUT_TXT, 'w') as fout:
    shutil.copyfileobj(fin, fout)

# Run the key recovery script and capture output
result = subprocess.run(['python', SCRIPT_PATH], capture_output=True, text=True)

# ✅ Add this debug line to inspect what the script actually printed
print("=== Script Output ===")
print(result.stdout)
print("=====================")

# Clean up temporary input file
os.remove(TEMP_INPUT_TXT)

# Extract recovered key from script output
recovered_key_line = next((line for line in result.stdout.splitlines() if 'Recovered AES Key:' in line), None)
if recovered_key_line:
    recovered_key = recovered_key_line.split(':')[-1].strip()
else:
    raise RuntimeError("Failed to extract recovered key from output")

# Load expected key
with open(EXPECTED_KEY_PATH, 'r') as f:
    expected_key = f.read().strip()

# Compare and report result
print("Recovered Key:", recovered_key)
print("Expected Key:", expected_key)
if recovered_key.lower() == expected_key.lower():
    print("\n✅ Test Passed: Recovered key matches expected key.")
else:
    print("\n❌ Test Failed: Recovered key does not match expected key.")
