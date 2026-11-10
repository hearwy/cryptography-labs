import math
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

from src.cipher import encrypt as xor_encrypt
from src.aes_cipher import encrypt_ecb, encrypt_ctr

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

def compute_correlation_pair(x: np.ndarray, y: np.ndarray) -> float:
    x = x.astype(np.float64)
    y = y.astype(np.float64)
    mean_x = np.mean(x)
    mean_y = np.mean(y)
    num = np.sum((x - mean_x) * (y - mean_y))
    den = np.sqrt(np.sum((x - mean_x) ** 2) * np.sum((y - mean_y) ** 2))
    if den == 0:
        return 0.0
    return float(num / den)

def compute_correlations(img_array: np.ndarray, max_samples: int = 50000) -> tuple[float, float]:
    # Горизонтальные пары
    h_pairs_x = img_array[:, :-1].flatten()
    h_pairs_y = img_array[:, 1:].flatten()

    # Вертикальные пары
    v_pairs_x = img_array[:-1, :].flatten()
    v_pairs_y = img_array[1:, :].flatten()

    if len(h_pairs_x) > max_samples:
        indices = np.random.choice(len(h_pairs_x), max_samples, replace=False)
        corr_h = compute_correlation_pair(h_pairs_x[indices], h_pairs_y[indices])
    else:
        corr_h = compute_correlation_pair(h_pairs_x, h_pairs_y)

    if len(v_pairs_x) > max_samples:
        indices = np.random.choice(len(v_pairs_x), max_samples, replace=False)
        corr_v = compute_correlation_pair(v_pairs_x[indices], v_pairs_y[indices])
    else:
        corr_v = compute_correlation_pair(v_pairs_x, v_pairs_y)

    return corr_h, corr_v

def compute_npcr_uaci(c1: bytes, c2: bytes) -> tuple[float, float]:
    min_len = min(len(c1), len(c2))
    a1 = np.frombuffer(c1[:min_len], dtype=np.uint8).astype(np.float64)
    a2 = np.frombuffer(c2[:min_len], dtype=np.uint8).astype(np.float64)

    npcr = float(np.mean(a1 != a2) * 100.0)
    uaci = float(np.mean(np.abs(a1 - a2) / 255.0) * 100.0)
    return npcr, uaci

def run_key_sensitivity_test(
    image_bytes: bytes,
    key1: str = "strong_secret_key_2026_a",
    key2: str = "strong_secret_key_2026_b"
) -> dict:
    nonce = b"\x00" * 16
    c1, _ = encrypt_ctr(image_bytes, key1, nonce=nonce)
    c2, _ = encrypt_ctr(image_bytes, key2, nonce=nonce)
    npcr, uaci = compute_npcr_uaci(c1, c2)
    return {
        "method": "AES-CTR (тест K1 vs K2)",
        "NPCR": npcr,
        "UACI": uaci
    }

def analyze_all(
    image_path: str,
    results_dir: str = "results",
    secret_key: str = "strong_secret_key_2026"
) -> list[dict]:
    img = Image.open(image_path)
    raw_bytes = img.tobytes()
    shape = (img.size[1], img.size[0]) if img.mode == "L" else (img.size[1], img.size[0], len(img.getbands()))

    xor_bytes = xor_encrypt(raw_bytes, secret_key)
    ecb_bytes = encrypt_ecb(raw_bytes, secret_key)[:len(raw_bytes)]
    ctr_bytes, _ = encrypt_ctr(raw_bytes, secret_key)

    variants = [
        ("Исходное изображение", raw_bytes),
        ("Потоковый XOR", xor_bytes),
        ("AES-ECB", ecb_bytes),
        ("AES-CTR", ctr_bytes),
    ]

    metrics_list = []
    Path(results_dir).mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.flatten()

    for idx, (label, data) in enumerate(variants):
        entropy = compute_entropy(data)

        arr_2d = np.frombuffer(data, dtype=np.uint8).reshape(shape)

        if len(shape) == 3:
            corr_h, corr_v = compute_correlations(arr_2d[:, :, 0])
        else:
            corr_h, corr_v = compute_correlations(arr_2d)

        metrics_list.append({
            "Метод": label,
            "Энтропия": round(entropy, 4),
            "Corr H": round(corr_h, 4),
            "Corr V": round(corr_v, 4),
        })

        axes[idx].hist(np.frombuffer(data, dtype=np.uint8), bins=256, range=(0, 256), color="steelblue", alpha=0.8)
        axes[idx].set_title(f"{label}\nЭнтропия: {entropy:.4f}")
        axes[idx].set_xlim(0, 256)
        axes[idx].grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(Path(results_dir) / "histograms.png", dpi=300)
    plt.close()

    return metrics_list