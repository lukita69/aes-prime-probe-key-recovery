import numpy as np
import gzip
import os
import matplotlib.pyplot as plt
import seaborn as sns
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import matplotlib

# Use non-interactive backend to allow saving figures in headless environments
matplotlib.use('Agg')

def load_data(filename):
    """
    Load plaintexts and timing data from a trace file (possibly gzipped).

    Args:
        filename (str): Path to the .txt or .gz trace file.

    Returns:
        np.ndarray: Array of plaintexts (N x 16, uint8).
        np.ndarray: Array of timing values (N x 64, float32).
    """
    pts, times = [], []
    opener = gzip.open if filename.endswith('.gz') else open
    with opener(filename, 'rt') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 66:
                continue
            pt_hex = parts[0]
            pts.append([int(pt_hex[i:i + 2], 16) for i in range(0, 32, 2)])
            times.append(list(map(int, parts[2:])))
    return np.array(pts, dtype=np.uint8), np.array(times, dtype=np.float32)

def _score_byte_sum(args):
    """
    Evaluate all 256 key byte guesses using summed timing values per cache line.

    Args:
        args (tuple): (byte_idx, plaintexts, timing values)

    Returns:
        int: Byte index
        int: Best key byte guess
        np.ndarray: 256x16 heatmap matrix (key guess x cache line)
    """
    byte_idx, pts, times_arr = args
    table_idx = byte_idx % 4
    table_times = times_arr[:, table_idx * 16:(table_idx + 1) * 16]
    scores = np.zeros(256, dtype=np.float32)
    heatmap = np.zeros((256, 16), dtype=np.float32)

    for k in range(256):
        predicted_lines = ((pts[:, byte_idx] ^ k) >> 4)
        summed = np.zeros(16, dtype=np.float32)
        for i, line in enumerate(predicted_lines):
            summed[line] += table_times[i, line]
        heatmap[k] = summed
        scores[k] = np.max(summed)

    best_guess = np.argmax(scores)
    return byte_idx, best_guess, heatmap

def recover_key_sum_only(pts, times_arr, processes=None):
    """
    Recover AES key (high nibble only) using the sum-max method.

    Args:
        pts (np.ndarray): Plaintext array (N x 16).
        times_arr (np.ndarray): Timing array (N x 64).
        processes (int, optional): Number of parallel workers.

    Returns:
        bytes: Best key guess (16 bytes, only high nibble correct).
        dict: Per-byte heatmap matrix.
    """
    if processes is None:
        processes = cpu_count()
    tasks = [(i, pts, times_arr) for i in range(16)]
    key_bytes = [0] * 16
    heatmaps = {}

    with Pool(processes) as pool:
        for byte_idx, best_guess, heatmap in tqdm(pool.imap_unordered(_score_byte_sum, tasks), total=16, desc="Processing Bytes"):
            key_bytes[byte_idx] = best_guess
            heatmaps[byte_idx] = heatmap

    return bytes(key_bytes), heatmaps

def generate_heatmaps_sum(heatmaps, out_dir="./report/heatmaps_sum"):
    """
    Generate and save heatmaps of summed timing values per high nibble.

    Args:
        heatmaps (dict): Dictionary of per-byte heatmap matrices (256x16).
        out_dir (str): Output directory path.
    """
    os.makedirs(out_dir, exist_ok=True)

    for byte_idx, matrix in sorted(heatmaps.items()):
        # Collapse 256x16 matrix into 16x16 by aggregating over high nibbles
        collapsed = np.zeros((16, 16), dtype=np.float32)
        for high in range(16):
            start = high * 16
            end = start + 16
            collapsed[high] = np.max(matrix[start:end], axis=0)

        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(collapsed, cmap='viridis',
                    xticklabels=[f"L{l}" for l in range(16)],
                    yticklabels=[f"0x{hn << 4:02x}" for hn in range(16)],
                    ax=ax)
        ax.set_title(f"Summed Timing: Byte {byte_idx} (Table {byte_idx % 4}) [High Nibbles Only]")
        ax.set_xlabel("Cache Line")
        ax.set_ylabel("High Nibble Guess")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"heatmap_byte_{byte_idx}.png"))
        plt.close(fig)

if __name__ == "__main__":
    # Load input traces
    pts, times = load_data("./data/output.txt.gz")
    # Perform key recovery
    key, heatmaps = recover_key_sum_only(pts, times)
    # Generate heatmaps for visualization
    generate_heatmaps_sum(heatmaps)
    # Print recovered key in hexadecimal format (high nibble only)
    print("Recovered key:", key.hex())
