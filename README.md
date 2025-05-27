# AES Prime+Probe Key Recovery

This project demonstrates a cache-based side-channel attack using the **Prime+Probe** technique to recover an AES encryption key. It targets T-table accesses during the **first round of AES**, analyzing timing data gathered via cache set probes.

## 📁 Project Structure

```
aes-prime-probe-key-recovery/
├── program/                        # Source code
│   └── key_recovery.py             # Main analysis and heatmap generation script
├── data/                           # Input trace files
│   └── output.txt.gz               # Compressed cache access trace
├── heatmaps/                       # Generated heatmaps (output)
├── report/                         # Written deliverables (PDFs)
│   ├── approach.pdf
│   ├── heatmap.pdf
│   └── info.txt
├── test/
│   ├── test_input_small.txt.gz     # A tiny input file with known behavior
│   ├── test_key_recovery.py        # Script to run tests and assert outputs
│   └── expected_key.txt            # Known key for test_input_small.txt.gz
├── requirements.txt                # Python dependencies
├── .gitignore                      # Files/directories to exclude from Git
└── README.md                       # This file
```

## ⚙️ Installation

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

Ensure `output.txt` or `output.txt.gz` is in the `data/` directory. Then run:

```bash
python program/key_recovery.py
```

This script:
- Analyzes cache access timings
- Correlates them with AES key byte candidates
- Generates heatmaps per key byte
- Recovers and prints the likely AES key

## 🔍 Methodology

- Each AES invocation generates timing data across 64 cache sets.
- The script evaluates all 256 key byte guesses for each of the 16 AES key positions.
- For each guess `k` at position `i`, it computes `index = plaintext[i] ⊕ k`, maps it to a cache set, and aggregates the corresponding access timing.
- The best guess is chosen by maximum aggregate timing correlation.
- Heatmaps visualize timing correlation intensity across key guesses and cache sets.

## 📊 Output

- **Heatmaps**: Saved in the `heatmaps/` directory (one per key byte).
- **Recovered AES Key**: Printed in hexadecimal format at the end of execution.

## 📄 License

This repository is intended for academic and educational use only. License terms can be added if the project is made public.
