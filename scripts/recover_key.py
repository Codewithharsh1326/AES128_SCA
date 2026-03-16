#!/usr/bin/env python3
"""
Phase 4 — Recover all 16 AES-128 key bytes using trained SCAAML models.

For each key byte the script:
  1. Runs the attack traces through the trained model (batch inference).
  2. Converts per-trace SubBytes-output predictions to key-byte log-probabilities
     using SCAAML's `ap_preds_to_key_preds` utility.
  3. Accumulates log-probabilities across traces (standard SCA key ranking).
  4. Records the NTD (Number of Traces to Disclosure) — the first trace count
     at which the correct key byte becomes the top-ranked candidate.

Prerequisites:
  - models/aes128/byte_NN.keras  created by scripts/train_attack.py
  - datasets/aes128/attack.npz   created by scripts/build_dataset.py

Usage (run from project root with venv active):
  python scripts/recover_key.py
"""

import numpy as np
import tensorflow as tf
from pathlib import Path

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

HW_LUT = np.array([bin(i).count("1") for i in range(256)])

def ap_preds_to_key_preds_hw(preds: np.ndarray, pts_byte: np.ndarray) -> np.ndarray:
    N = len(preds)
    sbox_in = pts_byte[:, np.newaxis] ^ np.arange(256, dtype=np.uint8)
    sbox_out = SBOX[sbox_in]
    hw_out = HW_LUT[sbox_out]
    row_indices = np.arange(N)[:, np.newaxis]
    return preds[row_indices, hw_out]

ALGORITHM    = "aes128"
ATTACK_POINT = "sub_bytes_out"
TRACE_LEN    = 54
BATCH_SIZE   = 256


def recover_byte(
    model_path: Path,
    attack_path: Path,
    attack_byte: int,
) -> tuple[int, int | None, int, list]:
    """
    Recover one key byte from the attack set.

    Returns:
        (recovered_key_byte, ntd, true_key_byte)
        ntd is None if the correct byte was never ranked first.
    """
    model = tf.keras.models.load_model(str(model_path))

    data       = np.load(attack_path)
    traces     = data["traces"][:, :TRACE_LEN, :]   # (N, 54, 1) float32
    pts_byte   = data["pts"][attack_byte]            # (N,)        uint8
    true_key_b = int(data["keys"][attack_byte][0])   # scalar — fixed key

    # Batch-predict all attack traces at once for efficiency
    preds = model.predict(traces, batch_size=BATCH_SIZE, verbose=0)  # (N, 256)

    # Convert SubBytes-output predictions → per-trace key-byte probabilities
    if preds.shape[1] == 9:
        key_probs_all = ap_preds_to_key_preds_hw(preds, pts_byte)
    else:
        key_probs_all = ap_preds_to_key_preds(preds, pts_byte, ATTACK_POINT)  # (N, 256)

    # Accumulate log-probabilities and find NTD
    log_key_probs = np.zeros(256, dtype=np.float64)
    ntd: int | None = None
    rank_history = []
    for i in range(len(traces)):
        log_key_probs += np.log(key_probs_all[i] + 1e-10)
        
        if attack_byte == 0:
            rank = np.count_nonzero(log_key_probs > log_key_probs[true_key_b])
            rank_history.append(rank)

        if ntd is None and np.argmax(log_key_probs) == true_key_b:
            ntd = i + 1

    recovered = int(np.argmax(log_key_probs))
    return recovered, ntd, true_key_b, rank_history


def main():
    models_dir  = Path(f"models/{ALGORITHM}")
    attack_path = Path(f"datasets/{ALGORITHM}/attack.npz")

    if not attack_path.exists():
        print(f"ERROR: {attack_path} not found. Run build_dataset.py first.")
        return

    n_attack = np.load(attack_path)["traces"].shape[0]
    print(f"Attack set: {n_attack} traces")
    print(f"{'Byte':>4}  {'True':>6}  {'Recovered':>9}  {'Match':>5}  {'NTD':>5}")
    print("─" * 42)

    recovered_key  = np.zeros(16, dtype=np.uint8)
    ntd_list: list[int] = []

    for b in range(16):
        model_path = models_dir / f"byte_{b:02d}.keras"
        if not model_path.exists():
            print(f"  {b:>4}  (model not found — run train_attack.py first)")
            continue

        rec, ntd, true_b, rank_history = recover_byte(model_path, attack_path, b)
        if b == 0 and rank_history:
            try:
                import matplotlib.pyplot as plt
                import sys
                graph_dir = Path("graphs" if "safe" not in sys.argv[0] else "graphs_safe")
                graph_dir.mkdir(exist_ok=True)
                plt.figure(figsize=(10, 6))
                plt.plot(range(1, len(rank_history) + 1), rank_history, color='blue', linewidth=2)
                plt.title("Rank of Correct Key vs. Number of Traces (Byte 0)")
                plt.xlabel("Number of Traces Processed")
                plt.ylabel("Rank (0 = Best)")
                plt.grid(True)
                plt.tight_layout()
                plt.savefig(graph_dir / "dl_ntd_rank.png")
                plt.close()
                print(f"\\n   Saved {graph_dir / 'dl_ntd_rank.png'}")
            except ImportError: pass
        recovered_key[b] = rec
        match   = "✓" if rec == true_b else "✗"
        ntd_str = str(ntd) if ntd is not None else "FAIL"
        print(f"  {b:>4}  0x{true_b:02x}    0x{rec:02x}       {match}    {ntd_str:>5}")
        if ntd is not None:
            ntd_list.append(ntd)

    print("─" * 42)
    data      = np.load(attack_path)
    true_key  = np.array([int(data["keys"][b][0]) for b in range(16)], dtype=np.uint8)
    n_correct = int(np.sum(recovered_key == true_key))

    print(f"\nKey recovery: {n_correct}/16 bytes correct")
    print(f"True key:      {true_key.tobytes().hex()}")
    print(f"Recovered key: {recovered_key.tobytes().hex()}")

    if ntd_list:
        print(f"\nNTD (traces to first correct rank):")
        print(f"  min={min(ntd_list)}  max={max(ntd_list)}  mean={np.mean(ntd_list):.1f}")

    if n_correct == 16:
        print("\n✓ Full key recovered — AES-128 SCA vulnerability demonstrated.")
    else:
        print(f"\n⚠  {16 - n_correct} byte(s) not recovered. "
              "Consider training more epochs or using more traces.")


if __name__ == "__main__":
    main()
