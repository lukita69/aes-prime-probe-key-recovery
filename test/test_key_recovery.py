# pytest test suite for key_recovery_cpa.py
import gzip
import os
import sys

import numpy as np

# Ensure 'program' directory is on sys.path for import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'program')))
from key_recovery_cpa import load_data, recover_key_bytes


def make_trace_lines(plaintexts, key_bytes, leak_scale=1.0, noise_scale=10.0):
    """
    Build ASCII lines for a small trace where each sample leaks the high nibble of each key byte.
    Returns list of strings: '<pt_hex> <ct_hex> t1...t64'. Ciphertext is dummy.
    """
    n, _ = plaintexts.shape
    lines = []
    for i in range(n):
        pt = plaintexts[i]
        ct = bytes([0] * 16).hex()
        times = np.random.normal(0, noise_scale, size=(64,))

        # Simulate realistic noise patterns
        drift = np.cumsum(np.random.normal(0, 0.01, size=(64,)))  # Slow drift
        burst = (np.random.rand() < 0.05) * np.random.normal(0, 50, size=(64,))  # Occasional burst
        correlated = np.random.normal(0, 1.0) * np.ones(64)  # Global offset
        times += drift + burst + correlated

        # Inject leakage
        for b in range(16):
            hi = (pt[b] ^ key_bytes[b]) >> 4
            table_idx = b % 4
            line_idx = table_idx * 16 + hi
            times[line_idx] += leak_scale

        line = f"{pt.tobytes().hex()} {ct} " + " ".join(f"{int(t)}" for t in times)
        lines.append(line)
    return lines


def write_trace_file(lines, path, gz=False):
    mode = 'wt'
    opener = gzip.open if gz else open
    with opener(path, mode) as f:
        for line in lines:
            f.write(line + "\n")


def test_recover_key_bytes_perfect(tmp_path):
    print("\n=== Test: recover_key_bytes_perfect ===")
    rng = np.random.default_rng(1234)
    n = 5000
    pts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    key = bytes(rng.integers(0, 256, size=(16,), dtype=np.uint8))
    print(f"Generated Key: {key.hex()}")

    lines = make_trace_lines(pts, key)
    trace_path = tmp_path / "trace.txt"
    write_trace_file(lines, str(trace_path), gz=False)
    print(f"Trace written to: {trace_path}")

    loaded_pts, loaded_times = load_data(str(trace_path))
    print(f"Loaded {loaded_pts.shape[0]} plaintexts")

    recovered_key, _, results = recover_key_bytes(loaded_pts, loaded_times, processes=1)
    print(f"Recovered Key: {recovered_key.hex()}")

    for idx, (orig, rec, (_, _, score)) in enumerate(zip(key, recovered_key, results)):
        print(f"Byte {idx:02}: Expected High Nibble {(orig >> 4):X}, Got {(rec >> 4):X} (Score={score:.4f})")
        assert (orig >> 4) == (rec >> 4)


def test_recover_key_bytes_with_gzip(tmp_path):
    """Test with gzipped file and high SNR."""
    rng = np.random.default_rng(5678)
    n = 50
    pts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    key = bytes(rng.integers(0, 256, size=(16,), dtype=np.uint8))
    lines = make_trace_lines(pts, key)
    path = tmp_path / "trace.txt.gz"
    write_trace_file(lines, str(path), gz=True)

    loaded_pts, loaded_times = load_data(str(path))
    recovered_key, _, _ = recover_key_bytes(loaded_pts, loaded_times, processes=2)
    for orig, rec in zip(key, recovered_key):
        assert (orig >> 4) == (rec >> 4)


def test_recover_key_bytes_random_noise(tmp_path):
    """Test with lower SNR, just ensure high nibble can still be extracted."""
    rng = np.random.default_rng(9012)
    n = 100
    pts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    key = bytes(rng.integers(0, 256, size=(16,), dtype=np.uint8))
    lines = make_trace_lines(pts, key)
    path = tmp_path / "trace2.txt"
    write_trace_file(lines, str(path), gz=False)

    loaded_pts, loaded_times = load_data(str(path))
    recovered_key, _, _ = recover_key_bytes(loaded_pts, loaded_times, processes=1)
    for orig, rec in zip(key, recovered_key):
        assert (orig >> 4) == (rec >> 4)
