# AES key (only high nibble) recovery from Prime+Probe cache attack output file using Mutual Information and CPA
#
# This script performs side-channel analysis using Mutual Information (MI)-based CPA
# to recover the upper 4 bits (high nibble) of each byte of a 128-bit AES key.
# Timing measurements from a Prime+Probe attack are used to correlate cache access
# patterns with predicted table indices derived from plaintext and key guesses.
#
# Features:
# - Outlier filtering using z-score
# - MI scoring for robustness against noise
# - Per-byte confidence score (difference between top MI scores)
# - Individual byte heatmaps + combined summary (matplotlib and Plotly)
# - Top guesses (per byte) export to CSV
#
# Usage:
#   python key_recovery_cpa_mi.py -i output.txt.gz -o recovered_key.txt \
#          --heatmap combined.png --heatmap-dir ./heatmaps --csv top_guesses.csv

import argparse
import gzip
import os
import csv
import numpy as np
from collections import defaultdict
from sklearn.metrics import mutual_info_score
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.io as pio
from tqdm import tqdm
from joblib import Parallel, delayed, cpu_count

def load_data(filename):
    """Load plaintext and cache timing data from gzipped or plain text file."""
    plaintexts, timings = [], []
    opener = gzip.open if filename.endswith(".gz") else open
    with opener(filename, "rt") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 66:
                continue  # skip malformed line
            pt = [int(parts[0][i:i + 2], 16) for i in range(0, 32, 2)]
            times = list(map(int, parts[2:]))
            if len(times) != 64:
                continue  # skip incomplete measurement
            plaintexts.append(pt)
            timings.append(times)
    return np.array(plaintexts, dtype=np.uint8), np.array(timings, dtype=np.float32)

def filter_outliers(pts, timings, z_thresh=3.0):
    """Remove samples where any timing value is too far from mean (z-score filter)."""
    z = np.abs((timings - timings.mean(axis=0)) / timings.std(axis=0))
    keep = (z < z_thresh).all(axis=1)
    return pts[keep], timings[keep]

def compute_mi(mask, values):
    """Compute mutual information between a binary mask and timing vector."""
    binned = np.digitize(values, np.histogram(values, bins=10)[1])
    return mutual_info_score(mask, binned)

def score_byte(idx, pts, timings):
    """Score key guesses for a single AES byte using MI and cache line timing."""
    print(f"[INFO] Processing byte {idx}")
    pt_byte = pts[:, idx]
    t_idx = idx % 4  # map byte to corresponding T-table
    relevant_timings = timings[:, t_idx * 16:(t_idx + 1) * 16]
    mi_matrix = np.zeros((256, 16))

    for k in range(256):
        predicted = np.bitwise_xor(pt_byte, k) // 16
        for line in range(16):
            mask = (predicted == line).astype(int)
            if mask.sum() == 0 or mask.sum() == len(mask):
                continue  # degenerate mask
            mi = compute_mi(mask, relevant_timings[:, line])
            mi_matrix[k, line] = mi

    scores = mi_matrix.max(axis=1)
    top5 = np.argsort(scores)[-5:][::-1]
    best = top5[0]
    conf = (scores[top5[0]] - scores[top5[1]]) / scores[top5[0]] if scores[top5[0]] != 0 else 0
    top_guesses = [(int(k), float(scores[k])) for k in top5]
    return idx, best, scores[best], conf, mi_matrix, top_guesses

def recover_all(pts, timings, procs):
    """Run CPA (MI-based) for all 16 AES key bytes in parallel using joblib with proper progress tracking."""
    tasks = (delayed(score_byte)(i, pts, timings) for i in range(16))
    with Parallel(n_jobs=procs, backend="loky") as parallel:
        results = []
        for result in tqdm(parallel(tasks), total=16, desc="Recovering key (true progress)"):
            results.append(result)

    results.sort(key=lambda x: x[0])
    key = bytes((r[1] & 0xF0) for r in results)
    confidences = [r[3] for r in results]
    matrices = {r[0]: r[4] for r in results}
    top_guesses_all = [(r[0], r[5]) for r in results]
    return key, confidences, matrices, top_guesses_all


def export_top_guesses(top_guesses_all, out_file):
    """Save top high nibble guesses per byte to CSV."""
    with open(out_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Byte', 'Rank', 'HighNibble', 'Score'])
        for byte_idx, guesses in top_guesses_all:
            grouped = defaultdict(list)
            for k, s in guesses:
                grouped[k & 0xF0].append((k, s))
            top_by_high = {
                high: max(glist, key=lambda x: x[1]) for high, glist in grouped.items()
            }
            sorted_hn = sorted(top_by_high.items(), key=lambda x: x[1][1], reverse=True)
            for rank, (hn, (_, score)) in enumerate(sorted_hn[:5], 1):
                writer.writerow([byte_idx, rank, f"{hn:02x}", f"{score:.5f}"])

def plot_combined_heatmap(matrices, out_path):
    """Create a summary heatmap of top MI scores per high nibble per byte."""
    collapsed = np.zeros((16, 16))
    for i in range(16):
        for hn in range(16):
            collapsed[i, hn] = np.max(matrices[i][hn*16:(hn+1)*16])
    plt.figure(figsize=(14, 6))
    sns.heatmap(collapsed, annot=False, xticklabels=[f"0x{hn << 4:02x}" for hn in range(16)],
                yticklabels=[f"B{i}" for i in range(16)], cmap="plasma")
    plt.title("MI-based CPA Heatmap (High Nibble)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    fig_plotly = px.imshow(collapsed, labels=dict(x="High Nibble", y="Key Byte", color="MI"),
                           x=[f"0x{hn << 4:02x}" for hn in range(16)],
                           y=[f"B{i}" for i in range(16)], color_continuous_scale='plasma')
    pio.write_html(fig_plotly, file=os.path.splitext(out_path)[0] + ".html", auto_open=False)

def plot_individual_heatmaps(matrices, out_dir):
    """Create individual heatmaps for each key byte guess vs. cache line."""
    os.makedirs(out_dir, exist_ok=True)
    for byte_index, matrix in matrices.items():
        heatmap_data = np.zeros((16, 16))
        for i in range(256):
            heatmap_data[i >> 4, i & 0xF] = np.max(matrix[i])
        plt.figure(figsize=(6, 5))
        sns.heatmap(heatmap_data, annot=False, cmap="plasma",
                    xticklabels=[f"{i:X}" for i in range(16)],
                    yticklabels=[f"{i:X}" for i in range(16)])
        plt.title(f"Byte {byte_index} MI Heatmap")
        plt.xlabel("Low nibble")
        plt.ylabel("High nibble")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"byte_{byte_index:02}.png"))
        plt.close()

def main():
    parser = argparse.ArgumentParser(description="AES high-nibble recovery using MI-CPA from Prime+Probe data")
    parser.add_argument("-i", "--input", required=True, help="Input trace file (.txt or .gz)")
    parser.add_argument("-o", "--output", required=True, help="Recovered key output path")
    parser.add_argument("--heatmap", default="heatmap.png", help="Combined heatmap image path")
    parser.add_argument("--heatmap-dir", default="heatmaps", help="Directory for per-byte heatmaps")
    parser.add_argument("--csv", help="CSV output of top guesses")
    parser.add_argument("--processes", type=int, default=cpu_count(), help="Number of processes")
    args = parser.parse_args()

    print("Loading data...")
    pts, timings = load_data(args.input)
    pts, timings = filter_outliers(pts, timings)
    print(f"Using {len(pts)} filtered samples.")

    print("Recovering key...")
    key, confs, matrices, top_guesses_all = recover_all(pts, timings, args.processes)
    print(f"[OK] Recovered AES key (high nibbles): {key.hex()}")
    print("Per-byte confidence scores:")
    for i, c in enumerate(confs):
        print(f"  Byte {i:02}: {c:.3f}")

    print("Saving key to file...")
    with open(args.output, "w") as f:
        f.write(key.hex())

    print("Plotting combined heatmap...")
    plot_combined_heatmap(matrices, args.heatmap)

    print("Plotting individual heatmaps...")
    plot_individual_heatmaps(matrices, args.heatmap_dir)
    print(f"Saved heatmaps to {args.heatmap} and directory {args.heatmap_dir}")

    if args.csv:
        print("Exporting CSV...")
        export_top_guesses(top_guesses_all, args.csv)
        print(f"Top guesses written to: {args.csv}")

if __name__ == "__main__":
    main()
