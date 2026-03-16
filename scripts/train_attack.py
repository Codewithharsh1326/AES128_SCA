#!/usr/bin/env python3
"""
Phase 4 — Train SCAAML ResNet model for AES-128 side-channel key recovery.

For each target key byte (0–15) the model learns to classify the AES SubBytes
output from a power trace, which is sufficient to recover the key byte via a
simple table lookup (SBOX inverse ^ plaintext).

Prerequisites:
  - datasets/aes128/train/*.npz and datasets/aes128/test/*.npz created by
    scripts/build_dataset.py

Outputs:
  models/aes128/byte_NN.keras   — best-val-acc checkpoint per key byte

Usage (run from project root with venv active):
  python scripts/train_attack.py            # train all 16 bytes
  python scripts/train_attack.py --byte 0  # train only byte 0 (quick test)
"""

import argparse
from pathlib import Path

import tensorflow as tf
from tensorflow import Tensor
from tensorflow.keras import layers, Model
from tensorflow.keras.optimizers import Adam
import tensorflow.keras.backend as K
from tensorflow.keras.callbacks import ModelCheckpoint, ReduceLROnPlateau


def tf_cap_memory():
    import tensorflow as tf
    try:
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
    except: pass

# ── Dataset paths (relative to project root) ─────────────────────────────────
ALGORITHM        = "aes128"
ATTACK_POINT     = "sub_bytes_out"
TRAIN_GLOB       = f"datasets/{ALGORITHM}/train/*"
TEST_GLOB        = f"datasets/{ALGORITHM}/test/*"

# ── Shard parameters (must match build_dataset.py) ───────────────────────────
N_TRAIN_SHARDS   = 32
N_TEST_SHARDS    = 4
TRACES_PER_SHARD = 250
TRACE_LEN        = 54

# ── Training hyper-parameters ────────────────────────────────────────────────
BATCH_SIZE = 256
EPOCHS     = 50

# ── ResNet1D config tuned for 54-sample traces ───────────────────────────────
# initial_pool_size=1 preserves all 54 samples; four stride-2 stacks reduce
# spatial dim: 54 → 27 → 13 → 6 → 3 before GlobalAvgPool.
MODEL_CFG = {
    "initial_pool_size": 1,
    "initial_filters"  : 4,
    "block_kernel_size": 3,
    "activation"       : "relu",
    "dense_dropout"    : 0.2,
    "blocks_stack1"    : 2,
    "blocks_stack2"    : 2,
    "blocks_stack3"    : 2,
    "blocks_stack4"    : 2,
}
LR = 1e-3


# ── ResNet1D (adapted from scaaml/intro/model.py, Keras-3 compatible) ────────

def create_dataset(glob_pattern, attack_point, attack_byte, num_shards, num_traces_per_shard, max_trace_length):
    import glob, numpy as np
    files = sorted(glob.glob(glob_pattern))[:num_shards]
    x_list, y_list = [], []
    for f in files:
        data = np.load(f)
        x_list.append(data["traces"][:num_traces_per_shard, :max_trace_length, :])
        y_list.append(data[attack_point][attack_byte][:num_traces_per_shard])
    x = np.concatenate(x_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    import tensorflow as tf
    y = tf.keras.utils.to_categorical(y, 256)
    return x, y

def build_model(input_shape: tuple, cfg: dict) -> Model:
    inputs = layers.Input(shape=input_shape)
    x = layers.Flatten()(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.Dense(128, activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(128, activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    outputs = layers.Dense(9, activation="softmax")(x)

    model = Model(inputs=inputs, outputs=outputs)
    model.compile(
        loss="categorical_crossentropy",
        metrics=["acc"],
        optimizer=Adam(LR),
    )
    return model



# ── Training loop ─────────────────────────────────────────────────────────────

def train_byte(attack_byte: int, models_dir: Path) -> float:
    print(f"\n── Key byte {attack_byte:02d} ──────────────────────────────────────")

    x_train, y_train = create_dataset(
        TRAIN_GLOB,
        attack_point=ATTACK_POINT,
        attack_byte=attack_byte,
        num_shards=N_TRAIN_SHARDS,
        num_traces_per_shard=TRACES_PER_SHARD,
        max_trace_length=TRACE_LEN,
    )
    x_test, y_test = create_dataset(
        TEST_GLOB,
        attack_point=ATTACK_POINT,
        attack_byte=attack_byte,
        num_shards=N_TEST_SHARDS,
        num_traces_per_shard=TRACES_PER_SHARD,
        max_trace_length=TRACE_LEN,
    )

    import numpy as np
    hw_lut = np.array([bin(i).count("1") for i in range(256)])
    y_train = tf.keras.utils.to_categorical(hw_lut[np.argmax(y_train, axis=1)], 9)
    y_test = tf.keras.utils.to_categorical(hw_lut[np.argmax(y_test, axis=1)], 9)

    K.clear_session()
    model = build_model(x_train.shape[1:], MODEL_CFG)
    model.summary(print_fn=lambda s: None)  # suppress summary clutter

    model_path = models_dir / f"byte_{attack_byte:02d}.keras"
    callbacks = [
        ModelCheckpoint(
            monitor="val_acc", filepath=str(model_path),
            save_best_only=True, mode="max", verbose=0,
        ),
        ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=5, min_lr=1e-5, verbose=1,
        ),
    ]

    history = model.fit(
        x_train, y_train,
        validation_data=(x_test, y_test),
        batch_size=BATCH_SIZE,
        epochs=EPOCHS,
        callbacks=callbacks,
        verbose=1,
    )

    # ── Plot Training History ─────────────────────────────────────────────────
    try:
        import matplotlib.pyplot as plt
        import sys
        graph_dir = Path("graphs" if "safe" not in sys.argv[0] else "graphs_safe")
        graph_dir.mkdir(exist_ok=True)
        
        plt.figure(figsize=(12, 5))
        
        plt.subplot(1, 2, 1)
        plt.plot(history.history['acc'], label='Train Accuracy')
        plt.plot(history.history['val_acc'], label='Validation Accuracy')
        plt.title(f'Model Accuracy (Byte {attack_byte})')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        plt.grid(True)
        
        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'], label='Train Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title(f'Model Loss (Byte {attack_byte})')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        plt.grid(True)
        
        plt.tight_layout()
        plt.savefig(graph_dir / f"training_history_byte_{attack_byte:02d}.png")
        plt.close()
    except ImportError:
        pass

    best_val_acc = max(history.history.get("val_acc", [0.0]))
    print(f"  → byte {attack_byte:02d} best val_acc = {best_val_acc:.4f}")
    return best_val_acc


def main():
    parser = argparse.ArgumentParser(
        description="Train SCAAML AES-128 SCA attack models"
    )
    parser.add_argument(
        "--byte", "-b", type=int, default=None,
        help="Key byte index (0–15). Omit to train all 16.",
    )
    args = parser.parse_args()

    tf_cap_memory()

    models_dir = Path(f"models/{ALGORITHM}")
    models_dir.mkdir(parents=True, exist_ok=True)

    bytes_to_train = [args.byte] if args.byte is not None else list(range(16))

    results: dict = {}
    for b in bytes_to_train:
        results[b] = train_byte(b, models_dir)

    print("\n══ Training Summary ═══════════════════════════════")
    for b, acc in sorted(results.items()):
        bar = "█" * int(acc * 20)
        print(f"  byte {b:02d}: val_acc={acc:.4f}  {bar}")


if __name__ == "__main__":
    main()
