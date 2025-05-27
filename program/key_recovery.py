import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
import gzip
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

# Constants
N_CACHE_SETS = 64
N_KEY_BYTES = 16
N_KEY_GUESSES = 256
CHUNK_SIZE = 10000  # lines per chunk for multiprocessing

# Global shared stats array
key_guesses_stats = np.zeros((N_KEY_BYTES, N_KEY_GUESSES, N_CACHE_SETS), dtype=np.float64)

# Function to parse a line of output.txt and return plaintext and CL values
def parse_line(line):
    parts = line.strip().split()
    if len(parts) < 66:
        return None, None
    plaintext_hex = parts[0]
    plaintext_bytes = bytes.fromhex(plaintext_hex)
    cache_accesses = list(map(int, parts[2:66]))
    return plaintext_bytes, cache_accesses

# Analyze a chunk of lines (for multiprocessing)
def process_chunk(lines):
    local_stats = np.zeros((N_KEY_BYTES, N_KEY_GUESSES, N_CACHE_SETS), dtype=np.float64)
    for line in lines:
        plaintext, cache_sets = parse_line(line)
        if plaintext is None:
            continue
        for byte_index in range(N_KEY_BYTES):
            for key_guess in range(N_KEY_GUESSES):
                index = plaintext[byte_index] ^ key_guess
                cache_set = index % N_CACHE_SETS
                local_stats[byte_index, key_guess, cache_set] += cache_sets[cache_set]
    return local_stats

# Read and split file into chunks
def chunked_file_read(filepath, chunk_size):
    if filepath.endswith('.gz'):
        opener = gzip.open
        mode = 'rt'
    else:
        opener = open
        mode = 'r'

    with opener(filepath, mode) as f:
        chunk = []
        for line in f:
            chunk.append(line)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

# Determine which file to read

def get_input_file():
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    path_txt = os.path.join(data_dir, "output.txt")
    path_gz = os.path.join(data_dir, "output.txt.gz")
    if os.path.exists(path_txt):
        return path_txt
    elif os.path.exists(path_gz):
        return path_gz
    else:
        raise FileNotFoundError("Neither output.txt nor output.txt.gz found in the data directory")

# Main analysis routine using multiprocessing
def analyze_output_parallel(file_path):
    global key_guesses_stats
    chunks = list(chunked_file_read(file_path, CHUNK_SIZE))
    with Pool(cpu_count()) as pool:
        for result in tqdm(pool.imap_unordered(process_chunk, chunks), total=len(chunks), desc="Processing chunks"):
            key_guesses_stats += result

# Visualization
def generate_heatmaps(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for byte_index in range(N_KEY_BYTES):
        plt.figure(figsize=(14, 6))
        sns.heatmap(key_guesses_stats[byte_index], cmap="YlGnBu")
        plt.title(f"Heatmap for Key Byte {byte_index}")
        plt.xlabel("Cache Set")
        plt.ylabel("Key Guess")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"heatmap_key_byte_{byte_index}.png"))
        plt.close()

# Extract the most likely key bytes
def extract_key():
    recovered_key = []
    for byte_index in range(N_KEY_BYTES):
        total_timings = key_guesses_stats[byte_index].sum(axis=1)
        best_guess = np.argmax(total_timings)
        recovered_key.append(best_guess)
    return recovered_key

# Entry point
if __name__ == "__main__":
    input_file = get_input_file()
    analyze_output_parallel(input_file)
    generate_heatmaps("heatmaps")
    key = extract_key()
    key_hex = ''.join(f'{b:02x}' for b in key)
    print("\nRecovered AES Key:", key_hex)
    print("Analysis complete. Heatmaps saved in 'heatmaps' directory.")
