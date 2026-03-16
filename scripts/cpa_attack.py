#!/usr/bin/env python3
"""
Phase 4 — Correlation Power Analysis (CPA) AES-128 key recovery.

CPA (Kocher et al. 1998) correlates a hypothetical power model with
observed power traces to recover the secret key. For unmasked AES-128
with Hamming-Weight leakage this recovers all 16 key bytes without any
ML training.

Attack model: HW(SubBytes(plaintext[b] XOR key[b]))  (Round 1, byte b)

Reads:
  data/traces.npy      (N, 54)  float32  power proxy (HW of new_sboxw)
  data/plaintexts.npy  (N, 16)  uint8    AES-128 plaintexts
  data/key.npy         (16,)    uint8    ground-truth key (for verification)

Usage (run from project root with venv active):
  python scripts/cpa_attack.py
  python scripts/cpa_attack.py --traces 500   # limit attack traces
"""

import argparse
import sys
import numpy as np
from pathlib import Path

# AES S-Box (FIPS-197 Figure 7)
SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
], dtype=np.uint8)

# Precomputed Hamming-Weight lookup table (0..255 → 0..8)
_HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)


def _hyp_hw(plaintexts_byte: np.ndarray) -> np.ndarray:
    """
    Build the (N, 256) hypothetical-HW matrix for all 256 key candidates.

    hyp[i, k] = HW(SBOX[pt[i] ^ k])
    """
    # pt XOR every key candidate: (N, 256)
    xor_all = plaintexts_byte[:, np.newaxis] ^ np.arange(256, dtype=np.uint8)
    return _HW[SBOX[xor_all]]  # (N, 256)


def cpa_attack(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    byte_idx: int,
) -> tuple[int, np.ndarray, np.ndarray]:
    """
    Full-N CPA on one key byte.

    Returns:
        recovered_key_byte (int)
        max_corr_per_key   (ndarray, shape (256,)) — max |r| across all timesteps
        corr               (ndarray, shape (256, T)) — full correlation traces
    """
    N, T = traces.shape
    hyp = _hyp_hw(plaintexts[:, byte_idx])  # (N, 256)

    # Pearson correlation via the sum-based formula (numerically stable, O(NTK))
    # r(k, t) = [N * Σ(hyp_k * trace_t) - Σhyp_k * Σtrace_t]
    #           / sqrt([N*Σhyp_k² - (Σhyp_k)²] * [N*Σtrace_t² - (Σtrace_t)²])
    n = N
    sum_h  = hyp.sum(axis=0)           # (256,)
    sum_h2 = (hyp ** 2).sum(axis=0)   # (256,)
    sum_t  = traces.sum(axis=0)        # (T,)
    sum_t2 = (traces.astype(np.float64) ** 2).sum(axis=0)  # (T,)
    sum_ht = hyp.T @ traces.astype(np.float64)             # (256, T)

    num    = n * sum_ht - sum_h[:, None] * sum_t[None, :]                 # (256, T)
    denom  = (np.sqrt(np.maximum(n * sum_h2 - sum_h ** 2, 0))[:, None] *
              np.sqrt(np.maximum(n * sum_t2 - sum_t ** 2, 0))[None, :])  # (256, T)
    corr   = num / np.where(denom < 1e-10, 1e-10, denom)                 # (256, T)

    max_corr = np.abs(corr).max(axis=1)   # (256,)  — best |r| per hypothesis
    return int(np.argmax(max_corr)), max_corr, corr


def cpa_ntd(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    byte_idx: int,
    true_key_byte: int,
    return_history: bool = False,
) -> tuple[int | None, dict | None]:
    """
    Find NTD: the minimum trace count at which the correct key hypothesis
    becomes rank-1, using an incremental running CPA.

    Complexity: O(N × T × 256)  — fast for N=10k, T=54.
    """
    N, T = traces.shape
    hyp = _hyp_hw(plaintexts[:, byte_idx])  # (N, 256)

    sum_h  = np.zeros(256)
    sum_h2 = np.zeros(256)
    sum_t  = np.zeros(T)
    sum_t2 = np.zeros(T)
    sum_ht = np.zeros((256, T))
    history = {'n': [], 'true_corr': [], 'max_wrong_corr': []} if return_history else None
    ntd = None

    for i in range(N):
        h = hyp[i]                    # (256,)
        t = traces[i].astype(np.float64)  # (T,)
        sum_h  += h
        sum_h2 += h ** 2
        sum_t  += t
        sum_t2 += t ** 2
        sum_ht += np.outer(h, t)

        n = i + 1
        if n < 2:
            continue

        num   = n * sum_ht - sum_h[:, None] * sum_t[None, :]
        dh    = np.sqrt(np.maximum(n * sum_h2 - sum_h ** 2, 0))
        dt    = np.sqrt(np.maximum(n * sum_t2 - sum_t ** 2, 0))
        denom = dh[:, None] * dt[None, :]
        corr  = num / np.where(denom < 1e-10, 1e-10, denom)

        if return_history:
            if n % 10 == 0 or n == N:
                max_corrs = np.abs(corr).max(axis=1)
                history['n'].append(n)
                history['true_corr'].append(max_corrs[true_key_byte])
                max_wrong = -1
                for k in range(256):
                    if k != true_key_byte and max_corrs[k] > max_wrong:
                        max_wrong = max_corrs[k]
                history['max_wrong_corr'].append(max_wrong)
                
                # Keep finding NTD even if we are returning history
                if ntd is None and np.argmax(max_corrs) == true_key_byte:
                    ntd = n
        else:
            if np.argmax(np.abs(corr).max(axis=1)) == true_key_byte:
                return n, None   # first trace count where correct key is rank-1

    return ntd if return_history else None, history if return_history else None


def main():
    parser = argparse.ArgumentParser(
        description="CPA key recovery on AES-128 power traces"
    )
    parser.add_argument(
        "--traces", "-n", type=int, default=None,
        help="Number of traces to use (default: all).",
    )
    parser.add_argument(
        "--ntd", action="store_true",
        help="Also compute NTD per byte (adds ~1 sec per byte).",
    )
    args = parser.parse_args()

    traces     = np.load("data/traces.npy").astype(np.float64)
    plaintexts = np.load("data/plaintexts.npy")
    true_key   = np.load("data/key.npy")

    if args.traces is not None:
        if args.traces <= 0:
            parser.error(f"--traces must be a positive integer, got {args.traces}")
        traces     = traces[:args.traces]
        plaintexts = plaintexts[:args.traces]

    N, T = traces.shape
    print(f"CPA attack: {N} traces × {T} samples, 16 key bytes")
    print()
    print(f"{'Byte':>4}  {'True':>6}  {'Recovered':>9}  {'Match':>5}  "
          f"{'Max|r|':>7}  {'NTD' if args.ntd else '':>5}")
    print("─" * (52 if args.ntd else 42))

    recovered_key = np.zeros(16, dtype=np.uint8)
    ntd_list: list[int] = []
    corr_traces_to_plot = None

    for b in range(16):
        rec, max_corr, corr_full = cpa_attack(traces, plaintexts, b)
        if b == 0:
            corr_traces_to_plot = corr_full
        recovered_key[b] = rec
        true_b   = int(true_key[b])
        match    = "✓" if rec == true_b else "✗"
        best_r   = max_corr[rec]

        ntd_str = ""
        if args.ntd:
            ntd, hist = cpa_ntd(traces, plaintexts, b, true_b, return_history=(b==0))
            if b == 0 and hist is not None:
                try:
                    import matplotlib.pyplot as plt
                    import sys
                    graph_dir = Path("graphs" if "safe" not in sys.argv[0] else "graphs_safe")
                    graph_dir.mkdir(exist_ok=True)
                    plt.figure(figsize=(10, 6))
                    plt.plot(hist['n'], hist['true_corr'], color='red', linewidth=2, label='Correct Key')
                    plt.plot(hist['n'], hist['max_wrong_corr'], color='grey', alpha=0.7, label='Best Wrong Key')
                    plt.title("CPA Correlation Convergence vs Traces (Byte 0)")
                    plt.xlabel("Number of Traces Processed")
                    plt.ylabel("Max Absolute Correlation")
                    plt.legend()
                    plt.grid(True)
                    plt.tight_layout()
                    plt.savefig(graph_dir / "cpa_convergence.png")
                    plt.close()
                    print(f"   Saved {graph_dir / 'cpa_convergence.png'}")
                except ImportError: pass
            ntd_str = str(ntd) if ntd else "FAIL"
            if ntd:
                ntd_list.append(ntd)

        print(f"  {b:>4}  0x{true_b:02x}    0x{rec:02x}       {match}    "
              f"{best_r:>7.4f}  {ntd_str:>5}")

    print("─" * (52 if args.ntd else 42))
    n_correct = int(np.sum(recovered_key == true_key))
    print(f"\nKey recovery: {n_correct}/16 bytes correct")
    print(f"True key:      {true_key.tobytes().hex()}")
    print(f"Recovered key: {recovered_key.tobytes().hex()}")

    # ── Plot CPA Correlation ──────────────────────────────────────────────────
    if corr_traces_to_plot is not None:
        try:
            import matplotlib.pyplot as plt
            graph_dir = Path("graphs" if "safe" not in sys.argv[0] else "graphs_safe")
            graph_dir.mkdir(exist_ok=True)
            
            plt.figure(figsize=(10, 6))
            true_k = true_key[0]
            for k in range(256):
                if k == true_k:
                    continue
                plt.plot(np.abs(corr_traces_to_plot[k]), color="grey", alpha=0.3, label="Wrong Guesses" if k==0 or (k==1 and true_k==0) else "")
            
            plt.plot(np.abs(corr_traces_to_plot[true_k]), color="red", linewidth=2, label=f"Correct Key (0x{true_k:02x})")
            plt.title("CPA Correlation vs. Time (Byte 0)")
            plt.xlabel("Clock Cycles")
            plt.ylabel("Absolute Correlation")
            plt.legend()
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(graph_dir / "cpa_correlation.png")
            plt.close()
            print(f"\n   Saved {graph_dir / 'cpa_correlation.png'}")
        except ImportError:
            print("\n   ⚠ matplotlib not installed, skipping plot generation.")

    if args.ntd and ntd_list:
        print(f"\nNTD: min={min(ntd_list)}  max={max(ntd_list)}  "
              f"mean={np.mean(ntd_list):.0f}")

    if n_correct == 16:
        print("\n✓ Full key recovered — AES-128 SCA vulnerability demonstrated.")
    else:
        failed = [b for b in range(16) if recovered_key[b] != true_key[b]]
        print(f"\n✗ Bytes not recovered: {failed}")
        sys.exit(1)


if __name__ == "__main__":
    main()
