#!/usr/bin/env python3
"""
Phase 3: Power Trace Extraction
================================
Parses data/aes_sim.vcd and builds one simulated power trace per AES-128
encryption.

Power proxy:
    Hamming Weight of new_sboxw[31:0] sampled at every positive clock edge
    inside the encryption window (next ↑ → ready ↑).  This is the direct
    S-Box output — the primary leakage point in an unprotected AES core.

Outputs written to data/:
    traces.npy       (N, T) float32   — HW power proxy, T ≈ 53–55 cycles
    plaintexts.npy   (N, 16) uint8    — raw plaintext bytes
    ciphertexts.npy  (N, 16) uint8    — raw ciphertext bytes
    key.npy          (16,) uint8      — fixed key bytes

Usage (from project root):
    source .venv/bin/activate
    python scripts/extract_traces.py
"""

import bisect
import csv
import sys
from pathlib import Path

import numpy as np
import vcdvcd

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT     = Path(__file__).resolve().parent.parent
VCD_PATH = ROOT / "data_safe" / "aes_sim.vcd"
CSV_PATH = ROOT / "data_safe" / "pt_ct.csv"
OUT_DIR  = ROOT / "data_safe"

FIXED_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
N_ENC = 10_000

# ── Signal names (vcdvcd requires bit-width suffix for multi-bit signals) ────
SIG_CLK      = "aes_tb.clk"
SIG_NEXT     = "aes_tb.next"
SIG_READY    = "aes_tb.ready"
SIG_NEW_SBOXW = "aes_tb.new_sboxw[31:0]"   # S-Box output — leakage point


# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_bin(s: str) -> int:
    """Parse binary string, treating 'x'/'z' as 0."""
    return int(s.replace("x", "0").replace("z", "0"), 2)


def hw(val: int) -> int:
    return bin(val).count("1")


def rising_edges(tv: list) -> list:
    """Return timestamps of 0→1 transitions in a signal's tv list."""
    edges, prev = [], "0"
    for t, v in tv:
        if prev != "1" and v == "1":
            edges.append(t)
        prev = v
    return edges


def build_sampler(tv: list):
    """
    Return a callable f(ts) → int  that gives the signal's integer value
    at timestamp ts using binary search (O(log n)).
    """
    times  = [t for t, _ in tv]
    values = [v for _, v in tv]

    def sample(ts: int) -> int:
        idx = bisect.bisect_right(times, ts) - 1
        if idx < 0:
            return 0
        return parse_bin(values[idx])

    return sample


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # Guard: inputs must exist
    if not VCD_PATH.exists():
        sys.exit(
            f"ERROR: VCD not found at {VCD_PATH}\n"
            "Re-run simulation from project root:\n"
            "  iverilog -o /tmp/aes_sim AES_128/rtl/aes_sbox.v \\\n"
            "    AES_128/rtl/aes_key_mem.v AES_128/rtl/aes_encipher_block.v \\\n"
            "    AES_128/rtl/aes_core.v AES_128/tb/aes_tb.v && vvp /tmp/aes_sim"
        )
    if not CSV_PATH.exists():
        sys.exit(f"ERROR: CSV not found at {CSV_PATH}")

    # ── Load VCD (selective signals → much faster on large files) ────────────
    size_mb = VCD_PATH.stat().st_size // 1_000_000
    print(f"[1/5] Loading VCD ({size_mb} MB) — this may take ~60 s …", flush=True)
    needed = [SIG_CLK, SIG_NEXT, SIG_READY, SIG_NEW_SBOXW]
    try:
        vcd = vcdvcd.VCDVCD(str(VCD_PATH), signals=needed)
    except TypeError:
        # Older vcdvcd without selective loading — fall back to full parse
        print("      (fallback: loading all signals)", flush=True)
        vcd = vcdvcd.VCDVCD(str(VCD_PATH))

    clk_tv   = vcd[SIG_CLK].tv
    next_tv  = vcd[SIG_NEXT].tv
    rdy_tv   = vcd[SIG_READY].tv
    sbox_tv  = vcd[SIG_NEW_SBOXW].tv

    # ── Positive clock edges ─────────────────────────────────────────────────
    print("[2/5] Building clock-edge index …", flush=True)
    pos_edges = sorted(t for t, v in clk_tv if v == "1")

    # ── Encryption windows ───────────────────────────────────────────────────
    print("[3/5] Finding encryption windows …", flush=True)
    next_rise = rising_edges(next_tv)
    rdy_rise  = rising_edges(rdy_tv)

    windows = []
    for t_next in next_rise:
        idx = bisect.bisect_right(rdy_rise, t_next)
        if idx < len(rdy_rise):
            windows.append((t_next, rdy_rise[idx]))

    if len(windows) != N_ENC:
        sys.exit(
            f"ERROR: expected {N_ENC} encryption windows, found {len(windows)}.\n"
            "Check that the VCD was generated with NUM_ENCRYPTIONS=10000."
        )
    print(f"       Found {len(windows)} windows ✓", flush=True)

    # ── Extract traces ───────────────────────────────────────────────────────
    print(f"[4/5] Extracting {N_ENC} traces …", flush=True)
    sample_sboxw = build_sampler(sbox_tv)

    raw_traces = []
    for i, (t_start, t_end) in enumerate(windows):
        if i % 1000 == 0:
            print(f"      {i:5d}/{N_ENC}", end="\r", flush=True)

        lo = bisect.bisect_left(pos_edges, t_start)
        hi = bisect.bisect_right(pos_edges, t_end)
        trace = [hw(sample_sboxw(t)) for t in pos_edges[lo:hi]]
        raw_traces.append(trace)

    lengths   = [len(t) for t in raw_traces]
    trace_len = min(lengths)
    print(
        f"\n       Trace lengths — min: {trace_len}  max: {max(lengths)}"
        f"  (trimmed to {trace_len})",
        flush=True,
    )
    traces = np.array([t[:trace_len] for t in raw_traces], dtype=np.float32)

    # ── Load plaintexts / ciphertexts from CSV ───────────────────────────────
    print("[5/5] Loading CSV and saving numpy arrays …", flush=True)
    plaintexts  = np.zeros((N_ENC, 16), dtype=np.uint8)
    ciphertexts = np.zeros((N_ENC, 16), dtype=np.uint8)
    seen_indices: set = set()

    with open(CSV_PATH, newline="") as f:
        for row in csv.DictReader(f):
            idx = int(row["index"])
            if idx < 0 or idx >= N_ENC:
                sys.exit(f"ERROR: CSV index {idx} out of range [0, {N_ENC})")
            if idx in seen_indices:
                sys.exit(f"ERROR: duplicate index {idx} in CSV")
            pt_hex = row["plaintext"]
            ct_hex = row["ciphertext"]
            if len(pt_hex) != 32 or len(ct_hex) != 32:
                sys.exit(f"ERROR: row {idx}: expected 32-char hex, "
                         f"got pt={len(pt_hex)} ct={len(ct_hex)}")
            seen_indices.add(idx)
            plaintexts[idx]  = np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8)
            ciphertexts[idx] = np.frombuffer(bytes.fromhex(ct_hex), dtype=np.uint8)

    if len(seen_indices) != N_ENC:
        missing = sorted(set(range(N_ENC)) - seen_indices)[:10]
        sys.exit(f"ERROR: CSV has {len(seen_indices)} rows, expected {N_ENC}. "
                 f"First missing indices: {missing}")

    key_bytes = np.frombuffer(bytes.fromhex(FIXED_KEY_HEX), dtype=np.uint8).copy()

    # ── Save ─────────────────────────────────────────────────────────────────
    OUT_DIR.mkdir(exist_ok=True)
    np.save(OUT_DIR / "traces.npy",      traces)
    np.save(OUT_DIR / "plaintexts.npy",  plaintexts)
    np.save(OUT_DIR / "ciphertexts.npy", ciphertexts)
    np.save(OUT_DIR / "key.npy",         key_bytes)

    print("\n✅  Extraction complete")
    print(f"   traces.npy      {traces.shape}  {traces.dtype}")
    print(f"   plaintexts.npy  {plaintexts.shape}  {plaintexts.dtype}")
    print(f"   ciphertexts.npy {ciphertexts.shape}  {ciphertexts.dtype}")
    print(f"   key.npy         {key_bytes.shape}  {key_bytes.dtype}")
    print(f"   key             = {FIXED_KEY_HEX}")

    # ── Sanity check: trace[0] should peak during Round 1 SubBytes ───────────
    r1_mean = traces[:, 1:5].mean()   # cycles 1-4: Round 1 SubBytes
    rest_mean = traces[:, 5:].mean()
    print(f"\n   Sanity: Round-1 SubBytes mean HW = {r1_mean:.2f}  "
          f"(rest mean = {rest_mean:.2f})")
    if r1_mean < rest_mean * 0.1:
        print("   ⚠  Round-1 HW unexpectedly low — check trace alignment.")
    else:
        print("   Trace alignment looks plausible ✓")

    # ── Plot Traces ──────────────────────────────────────────────────────────
    print("\n[6/5] Generating power trace plots...", flush=True)
    try:
        import matplotlib.pyplot as plt
        graph_dir = OUT_DIR.parent / ("graphs" if "safe" not in str(OUT_DIR) else "graphs_safe")
        graph_dir.mkdir(exist_ok=True)
        
        plt.figure(figsize=(10, 6))
        for i in range(min(10, len(traces))):
            plt.plot(traces[i], alpha=0.7, label=f"Trace {i}" if i==0 else "")
        plt.title("Sample Power Traces (Hamming Weight)")
        plt.xlabel("Clock Cycles")
        plt.ylabel("Hamming Weight")
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(graph_dir / "sample_power_traces.png")
        plt.close()
        print(f"   Saved {graph_dir / 'sample_power_traces.png'}")
    except ImportError:
        print("   ⚠ matplotlib not installed, skipping plot generation.")


if __name__ == "__main__":
    main()
