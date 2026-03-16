#!/usr/bin/env python3
"""
Phase 4 — Build SCAAML-compatible NPZ shard dataset.

Reads:
  data/traces.npy      (10000, 54)  float32  HW power proxy traces
  data/plaintexts.npy  (10000, 16)  uint8    AES-128 plaintexts
  data/key.npy         (16,)        uint8    fixed AES-128 key

Writes:
  datasets/aes128/train/shard_{n:04d}.npz   (32 shards × 250 traces = 8,000)
  datasets/aes128/test/shard_{n:04d}.npz    ( 4 shards × 250 traces = 1,000)
  datasets/aes128/attack.npz                (remaining 1,000 traces for recovery)

Shard NPZ format (SCAAML intro convention):
  traces        (N, T, 1)  float32   power traces — channel-last for Conv1D
  keys          (16, N)    uint8     repeated fixed key bytes
  pts           (16, N)    uint8     plaintext bytes per key position
  sub_bytes_in  (16, N)    uint8     AES SubBytes input  = pt[b] ^ key[b]
  sub_bytes_out (16, N)    uint8     AES SubBytes output = SBOX[sub_bytes_in]

Run from project root:
  python scripts/build_dataset.py
"""

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

TRACES_PER_SHARD = 250
N_TRAIN_SHARDS   = 32   # 32 × 250 = 8,000 train traces
N_TEST_SHARDS    = 4    #  4 × 250 = 1,000 test  traces
# remaining 1,000 → attack.npz


def _make_shard(traces_chunk, pts_chunk, key):
    """Pack one shard into the SCAAML intro NPZ dict."""
    N = len(traces_chunk)
    sbi = pts_chunk ^ key[np.newaxis, :]          # (N, 16) uint8  — SubBytes input
    sbo = SBOX[sbi]                                # (N, 16) uint8  — SubBytes output
    return dict(
        traces        = traces_chunk[:, :, np.newaxis].astype(np.float32),  # (N, T, 1)
        keys          = np.tile(key, (N, 1)).T.astype(np.uint8),            # (16, N)
        pts           = pts_chunk.T.astype(np.uint8),                       # (16, N)
        sub_bytes_in  = sbi.T.astype(np.uint8),                             # (16, N)
        sub_bytes_out = sbo.T.astype(np.uint8),                             # (16, N)
    )


def main():
    data_dir  = Path("data_safe")
    out_root  = Path("datasets_safe/aes128")
    train_dir = out_root / "train"
    test_dir  = out_root / "test"
    train_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    traces     = np.load(data_dir / "traces.npy")      # (10000, 54)
    plaintexts = np.load(data_dir / "plaintexts.npy")  # (10000, 16)
    key        = np.load(data_dir / "key.npy")          # (16,)

    print(f"Loaded {len(traces):,} traces  shape={traces.shape}  dtype={traces.dtype}")
    print(f"Key: {key.tobytes().hex()}")

    # --- Train shards ---
    n_train = N_TRAIN_SHARDS * TRACES_PER_SHARD
    for s in range(N_TRAIN_SHARDS):
        lo, hi = s * TRACES_PER_SHARD, (s + 1) * TRACES_PER_SHARD
        shard = _make_shard(traces[lo:hi], plaintexts[lo:hi], key)
        np.savez_compressed(train_dir / f"shard_{s:04d}.npz", **shard)
    print(f"Wrote {N_TRAIN_SHARDS} train shards → {train_dir}/")

    # --- Test shards ---
    n_test = N_TEST_SHARDS * TRACES_PER_SHARD
    for s in range(N_TEST_SHARDS):
        lo = n_train + s * TRACES_PER_SHARD
        hi = lo + TRACES_PER_SHARD
        shard = _make_shard(traces[lo:hi], plaintexts[lo:hi], key)
        np.savez_compressed(test_dir / f"shard_{s:04d}.npz", **shard)
    print(f"Wrote {N_TEST_SHARDS}  test  shards → {test_dir}/")

    # --- Attack set ---
    lo = n_train + n_test
    attack = _make_shard(traces[lo:], plaintexts[lo:], key)
    np.savez_compressed(out_root / "attack.npz", **attack)
    n_attack = len(traces) - lo
    print(f"Wrote attack set: {n_attack} traces → {out_root}/attack.npz")

    # Sanity-check first shard
    sample = np.load(train_dir / "shard_0000.npz")
    assert sample["traces"].shape == (TRACES_PER_SHARD, traces.shape[1], 1), \
        f"Unexpected traces shape: {sample['traces'].shape}"
    assert sample["sub_bytes_out"].shape == (16, TRACES_PER_SHARD), \
        f"Unexpected sbo shape: {sample['sub_bytes_out'].shape}"
    # Spot-check S-Box for first trace, byte 0
    pt0, k0 = int(plaintexts[0, 0]), int(key[0])
    expected_sbo = int(SBOX[pt0 ^ k0])
    actual_sbo   = int(sample["sub_bytes_out"][0, 0])
    assert actual_sbo == expected_sbo, \
        f"S-Box mismatch byte0: expected {expected_sbo:#04x}, got {actual_sbo:#04x}"

    print(f"\n✓ Sanity checks passed")
    print(f"Dataset split: {n_train} train / {n_test} test / {n_attack} attack")


if __name__ == "__main__":
    main()
