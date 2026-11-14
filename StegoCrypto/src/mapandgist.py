import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

AMPLIFICATION_FACTOR = 255

def _load_rgb_int16(image_path: str) -> np.ndarray:
    return np.array(Image.open(image_path).convert("RGB"), dtype=np.int16)

def save_difference_map(
    cover_path: str,
    plain_path: str,
    encrypted_path: str,
    random_path: str,
    output_path: str,
) -> None:
    cover = _load_rgb_int16(cover_path)

    diff_plain = (np.abs(cover - _load_rgb_int16(plain_path)) * AMPLIFICATION_FACTOR).astype(np.uint8)
    diff_encrypted = (np.abs(cover - _load_rgb_int16(encrypted_path)) * AMPLIFICATION_FACTOR).astype(np.uint8)
    diff_random = (np.abs(cover - _load_rgb_int16(random_path)) * AMPLIFICATION_FACTOR).astype(np.uint8)

    panels = [
        ("source", cover.astype(np.uint8)),
        ("plain", diff_plain),
        ("encrypted", diff_encrypted),
        ("encrypted random", diff_random),
    ]

    fig, axes = plt.subplots(1, 4, figsize=(16, 4.5), dpi=150, facecolor="white")

    for ax, (label, img_data) in zip(axes, panels):
        ax.imshow(img_data)
        ax.set_xlabel(label, fontsize=11, labelpad=8)

        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)

    plt.tight_layout(w_pad=2.0)
    plt.savefig(output_path, facecolor="white")
    plt.close(fig)

def save_comparison_histogram(
    cover_path: str,
    plain_path: str,
    encrypted_path: str,
    random_path: str,
    output_path: str,
) -> None:
    cover_flat = np.array(Image.open(cover_path).convert("RGB"), dtype=np.uint8).ravel()
    hist_cover = np.bincount(cover_flat, minlength=256).astype(np.float64)

    variants = [
        ("Plain LSB", plain_path),
        ("Encrypted LSB", encrypted_path),
        ("Encrypted Random LSB", random_path),
    ]

    bins = np.arange(256)
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.2), dpi=150, facecolor="white")

    for ax, (title, stego_path) in zip(axes, variants):
        stego_flat = np.array(Image.open(stego_path).convert("RGB"), dtype=np.uint8).ravel()
        hist_stego = np.bincount(stego_flat, minlength=256).astype(np.float64)

        max_val = max(hist_cover.max(), hist_stego.max(), 1.0)
        cover_pct = (hist_cover / max_val) * 100.0
        stego_pct = (hist_stego / max_val) * 100.0

        ax.plot(bins, cover_pct, color="#1a3cff", linewidth=0.9, label="Cover")
        ax.fill_between(bins, cover_pct, color="#1a3cff", alpha=0.25)

        ax.plot(bins, stego_pct, color="#e60000", linewidth=0.9, label="Stego")
        ax.fill_between(bins, stego_pct, color="#e60000", alpha=0.25)

        ax.set_title(title, fontsize=11, pad=12)
        ax.set_xlabel("Яркость пикселя", fontsize=10, labelpad=6)
        ax.set_ylabel("Относительная частота", fontsize=10, labelpad=6)

        ax.set_xlim(0, 255)
        ax.set_ylim(0, 102)
        ax.set_xticks([0, 255])
        ax.set_yticks([0, 100])
        ax.set_yticklabels(["0%", "100%"])
        ax.tick_params(length=0)

        for spine in ax.spines.values():
            spine.set_color("#cccccc")
            spine.set_linewidth(0.8)

    plt.tight_layout(w_pad=3.0)
    plt.savefig(output_path, facecolor="white")
    plt.close(fig)