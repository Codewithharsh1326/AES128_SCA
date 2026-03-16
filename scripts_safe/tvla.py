#!/usr/bin/env python3
"""
Test Vector Leakage Assessment (TVLA) — Welch's T-Test
======================================================
This script performs a fixed-vs-random (or bit-based) t-test to rigorously
prove the presence of side-channel leakage. In the SCA community, a t-value
exceeding +/- 4.5 indicates a highly significant leakage (confidence > 99.999%).

Usage:
  python scripts/tvla.py
"""

import sys
import numpy as np
from pathlib import Path

def welch_t_test(set0: np.ndarray, set1: np.ndarray) -> np.ndarray:
    """Computes Welch's t-test statistic for each time sample across two sets."""
    n0, n1 = len(set0), len(set1)
    if n0 == 0 or n1 == 0:
        return np.zeros(set0.shape[1] if n0 > 0 else set1.shape[1])
    
    mean0, mean1 = np.mean(set0, axis=0), np.mean(set1, axis=0)
    var0, var1 = np.var(set0, axis=0, ddof=1), np.var(set1, axis=0, ddof=1)
    
    # Avoid division by zero
    den = np.sqrt(var0/n0 + var1/n1)
    den = np.where(den == 0, 1e-10, den)
    
    return (mean0 - mean1) / den

def main():
    is_safe = "safe" in sys.argv[0]
    data_dir = "data_safe" if is_safe else "data"
    
    print(f"Loading traces from {data_dir}...")
    try:
        traces = np.load(f"{data_dir}/traces.npy").astype(np.float64)
        plaintexts = np.load(f"{data_dir}/plaintexts.npy")
    except FileNotFoundError:
        print(f"ERROR: Traces not found in {data_dir}/.")
        sys.exit(1)
        
    # We will partition traces based on the LSB of the first plaintext byte.
    # In a fully unprotected AES, this bit directly influences the SBox input,
    # causing diverging power consumptions depending on its value.
    bit_target = plaintexts[:, 0] & 1
    
    set0 = traces[bit_target == 0]
    set1 = traces[bit_target == 1]
    
    print(f"Set 0 (Bit=0): {len(set0)} traces")
    print(f"Set 1 (Bit=1): {len(set1)} traces")
    
    t_stat = welch_t_test(set0, set1)
    
    max_t = np.max(np.abs(t_stat))
    print(f"Maximum |t-value|: {max_t:.2f}")
    if max_t > 4.5:
        print("Result: SIGNIFICANT LEAKAGE DETECTED (|t| > 4.5)")
    else:
        print("Result: NO SIGNIFICANT LEAKAGE DETECTED (|t| <= 4.5)")
        
    try:
        import matplotlib.pyplot as plt
        graph_dir = Path("graphs_safe" if is_safe else "graphs")
        graph_dir.mkdir(exist_ok=True)
        
        plt.figure(figsize=(10, 6))
        plt.plot(t_stat, color='black', linewidth=1)
        plt.axhline(y=4.5, color='red', linestyle='--', label='Threshold (+4.5)')
        plt.axhline(y=-4.5, color='red', linestyle='--', label='Threshold (-4.5)')
        
        plt.title(f"TVLA T-Test (Plaintext Byte 0 LSB) - {'Safe' if is_safe else 'Vulnerable'} Core")
        plt.xlabel("Clock Cycles")
        plt.ylabel("T-Test Statistic")
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        
        out_file = graph_dir / "tvla_t_test.png"
        plt.savefig(out_file)
        plt.close()
        print(f"\nSaved graph to {out_file}")
    except ImportError:
        print("\nmatplotlib not installed, skipping plot.")

if __name__ == "__main__":
    main()
