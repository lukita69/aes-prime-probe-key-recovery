# AES Prime+Probe Key Recovery

This project implements and compares several techniques for recovering the **high nibbles** of a 128-bit AES key using cache access timing data obtained via a Prime+Probe side-channel attack. The side-channel leakage originates from lookup table accesses during AES encryption, and the analysis leverages this to infer partial key information.

## 📁 Project Structure

```
aes-prime-probe-key-recovery/
├── program/                        # Source code for each recovery method
│   ├── key_recovery_cpa.py         # CPA-based recovery (most accurate)
│   ├── key_recovery_cpa_mi.py      # CPA-based recovery with mutual information
│   ├── key_recovery_skit.py        # Experimental scikit-learn-based variant
│   ├── key_recovery_sum_avg.py     # Sum-Average-based heuristic key recovery approach
│   ├── key_recovery_sum_max.py     # Sum-Max-based heuristic key recovery approach
├── data/
│   └── output.txt.gz               # Compressed file containing plaintext, ciphertext, and cache timing data
├── report/                         # Written reports and visualizations
│   ├── heatmaps/                   # CPA-based heatmaps (per byte + combined)
│   ├── heatmaps_sum/               # Sum-Max heatmaps
│   ├── heatmaps_sumavg/            # Sum-Avg heatmaps
│   ├── approach.pdf                # Written explanation and results of implemented methods
│   ├── heatmap.pdf                 # Document containing representative heatmaps
│   └── info.txt                    # Notes or metadata
├── test/
│   ├── test_key_on_output_file.py  # Verifies key correctness against ciphertext
│   ├── test_key_recovery.py        # (Deprecated) Test automation script for key recovery — *not actively maintained*
│   └── expected_key.txt            # Expected key file used for testing
├── requirements.txt                # Python dependencies (numpy, matplotlib, seaborn, tqdm, etc.)
├── .gitignore                      # Files excluded from Git versioning
└── README.md                       # This file
```


## 🧪 Implemented Methods

Three distinct approaches are used to estimate key high nibbles from the timing data:

- **Sum-Max**:
  - For each key guess and byte position, timings are grouped per cache line.
  - The sum of access timings is calculated per line; the key with the highest maximum is selected.
  - Simple and fast, but sensitive to outliers.

- **Sum-Avg**:
  - Similar to Sum-Max, but uses average instead of sum to reduce noise.
  - More stable in noisy environments, though harder to interpret visually.

- **CPA (Correlation Power Analysis)**:
  - Statistically correlates expected cache access patterns (based on key guesses) with measured timing data.
  - Most accurate and robust method implemented.

- **CPA with Mutual Information**:
  - An extension of the CPA method that incorporates mutual information to enhance key recovery accuracy.
  - This method is still experimental and may not be fully optimized.
  - It uses the same basic structure as the CPA method but applies additional statistical techniques to improve results.

An additional method (`key_recovery_sckit.py`) explores experimental classification using scikit-learn, but is not currently part of the core analysis pipeline.

## 📊 Heatmap Visualization

Each method generates per-byte heatmaps that visualize the relative likelihood of different high nibble guesses. These are found under `report/heatmaps*/`.

- CPA also includes a **combined heatmap**, summarizing all 16 key bytes.
- Heatmaps use color intensity to indicate strength of timing correlation or magnitude.

## ⚙️ Dependencies

To install required Python packages:
```bash
pip install -r requirements.txt
```

## ▶️ Running a Key Recovery

Example usage (for the CPA method):
```bash
python key_recovery_cpa.py -i ./data/output.txt.gz -o ./report/recovered_key.txt -d ./report/heatmaps --csv .report/top_guesses.csv
```
Each script will:
1. Parse the trace data from data/output.txt.gz
2. Process cache timing and plaintext values
3. Recover the most likely high nibbles of the AES key
4. Output results and optionally generate heatmaps

## ⚠️ Notes

- This project recovers only the **high nibbles** (4 MSBs) of each AES key byte (64 bits total).
- The `test_key_recovery.py` script is currently unmaintained and may not reflect the latest logic or methods.
- Heatmaps provide valuable insight but may be harder to interpret in some methods (especially Sum-Avg).

## 📄 Author
This project was developed by Luka Kravos as part of a coursework assignment on side-channel attacks and cryptographic key recovery.
