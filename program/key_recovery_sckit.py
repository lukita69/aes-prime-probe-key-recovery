import gzip
import os
from multiprocessing import Pool, cpu_count

import matplotlib.pyplot as plt
import numpy as np
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.preprocessing import StandardScaler

# Constants defining dataset and AES layout
OUTPUT_FILE = "./data/output.txt.gz"  # Path to input trace file
CACHE_SETS = 64                       # Number of cache lines measured per encryption
KEY_BYTES = 16                        # AES uses 16 key bytes (128 bits)
NIBBLE_VALUES = 16                    # Possible high nibble values (4-bit)

def parse_output_file(path):
    """Load and parse plaintexts and cache access timings from the trace file."""
    plaintexts, timings = [], []
    with gzip.open(path, 'rt') as f:
        for line in f:
            parts = line.strip().split()
            pt = bytes.fromhex(parts[0])
            times = list(map(int, parts[2:2 + CACHE_SETS]))
            plaintexts.append(np.frombuffer(pt, dtype=np.uint8))
            timings.append(times)
    return np.array(plaintexts), np.array(timings)

def recover_nibble(args):
    """Recover the most likely high nibble of a key byte using Linear Discriminant Analysis (LDA)."""
    byte_index, plaintexts, timings_norm = args
    X, y = [], []
    for i in range(len(plaintexts)):
        nibble = (plaintexts[i][byte_index] >> 4) & 0xF  # Extract high nibble of plaintext byte
        X.append(timings_norm[i])
        y.append(nibble)

    lda = LinearDiscriminantAnalysis()
    lda.fit(X, y)  # Train classifier
    preds = lda.predict(X)  # Predict on training set

    # Confidence score for each nibble: mean prediction match
    scores = [np.mean(preds == n) for n in range(NIBBLE_VALUES)]

    return byte_index, int(np.argmax(scores)), scores

def generate_heatmap(scores_matrix, output_dir="heatmaps"):
    """Generate individual and combined heatmaps from prediction scores."""
    os.makedirs(output_dir, exist_ok=True)

    # Per-byte 1D heatmaps
    for byte_index, scores in enumerate(scores_matrix):
        data = np.array(scores).reshape(1, -1)
        plt.figure(figsize=(8, 1.2))
        plt.imshow(data, cmap='plasma', aspect='auto')
        plt.colorbar(label="Confidence Score", orientation='vertical')
        plt.xticks(range(16), [f"{i:x}" for i in range(16)])
        plt.yticks([0], [f"Byte {byte_index}"])
        plt.title(f"Heatmap for Key Byte {byte_index}")
        plt.tight_layout()
        plt.savefig(f"{output_dir}/heatmap_byte_{byte_index:02}.png")
        plt.close()

    # Combined 16x16 heatmap
    all_scores = np.array(scores_matrix)
    plt.figure(figsize=(10, 6))
    plt.imshow(all_scores, cmap='hot', aspect='auto')
    plt.colorbar(label="Confidence Score")
    plt.xticks(range(16), [f"{i:x}" for i in range(16)])
    plt.yticks(range(16), [f"Byte {i}" for i in range(16)])
    plt.title("Combined Heatmap of All Key Bytes")
    plt.xlabel("High Nibble Guess")
    plt.ylabel("Key Byte Index")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/combined_heatmap.png")
    plt.close()

def main():
    print("[*] Loading and parsing output...")
    plaintexts, timings = parse_output_file(OUTPUT_FILE)

    print("[*] Normalizing timings...")
    timings_norm = StandardScaler().fit_transform(timings)

    print("[*] Recovering high nibbles with LDA...")
    with Pool(cpu_count()) as pool:
        args = [(i, plaintexts, timings_norm) for i in range(KEY_BYTES)]
        results = pool.map(recover_nibble, args)

    results.sort()  # Sort by byte index
    recovered_key = ''.join(f'{nibble:x}?' for _, nibble, _ in results)
    print("\n[+] Recovered AES Key (High Nibbles Only):")
    print(recovered_key)

    print("[*] Generating heatmaps...")
    scores_matrix = [scores for _, _, scores in results]
    generate_heatmap(scores_matrix, output_dir="./report/heatmaps")

if __name__ == "__main__":
    main()
