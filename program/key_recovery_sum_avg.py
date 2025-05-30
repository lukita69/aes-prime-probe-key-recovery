import numpy as np
import gzip
import os
import matplotlib.pyplot as plt
import seaborn as sns
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import matplotlib

matplotlib.use('Agg')

def load_data(filename):
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

def _score_byte(args):
    byte_idx, pts, times_arr = args
    table_idx = byte_idx % 4
    table_times = times_arr[:, table_idx * 16:(table_idx + 1) * 16]
    scores = np.zeros(256, dtype=np.float32)
    heatmap = np.zeros((256, 16), dtype=np.float32)

    for k in range(256):
        predicted_lines = ((pts[:, byte_idx] ^ k) >> 4)
        summed = np.zeros(16, dtype=np.float32)
        counts = np.zeros(16, dtype=np.float32)

        for i, line in enumerate(predicted_lines):
            summed[line] += table_times[i, line]
            counts[line] += 1

        avg = np.divide(summed, counts, out=np.zeros_like(summed), where=counts != 0)
        heatmap[k] = avg
        scores[k] = np.max(avg)

    best_guess = np.argmax(scores)
    return byte_idx, best_guess, heatmap

def recover_key_simple(pts, times_arr, processes=None):
    if processes is None:
        processes = cpu_count()
    tasks = [(i, pts, times_arr) for i in range(16)]

    key_bytes = [0] * 16
    heatmaps = {}

    with Pool(processes) as pool:
        for byte_idx, best_guess, heatmap in tqdm(pool.imap_unordered(_score_byte, tasks), total=16, desc="Processing Bytes"):
            key_bytes[byte_idx] = best_guess
            heatmaps[byte_idx] = heatmap

    return bytes(key_bytes), heatmaps

def generate_heatmaps(heatmaps, out_dir="../report/heatmaps_sumavg"):
    os.makedirs(out_dir, exist_ok=True)

    for byte_idx, matrix in sorted(heatmaps.items()):
        # Collapse matrix from 256x16 to 16x16 (one row per high nibble)
        collapsed = np.zeros((16, 16), dtype=np.float32)
        for hn in range(16):
            rows = matrix[hn*16:(hn+1)*16]
            collapsed[hn] = np.max(rows, axis=0)

        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(collapsed, cmap='viridis',
                    xticklabels=[f"L{l}" for l in range(16)],
                    yticklabels=[f"0x{hn << 4:02x}" for hn in range(16)],
                    ax=ax)

        ax.set_title(f"Avg Timing (High Nibbles): Byte {byte_idx} (Table {byte_idx % 4})")
        ax.set_xlabel("Cache Line")
        ax.set_ylabel("High Nibble")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"heatmap_byte_{byte_idx}.png"))
        plt.close(fig)

if __name__ == "__main__":
    pts, times = load_data("../data/output.txt.gz")
    key, heatmaps = recover_key_simple(pts, times)
    generate_heatmaps(heatmaps)
    print("Recovered key:", key.hex())
