import csv
import os
import shutil

from PIL import Image

from src.lsb import (
    embed_lsb_encrypted,
    embed_lsb_plain,
    embed_lsb_random,
)
from src.mapandgist import (
    save_comparison_histogram,
    save_difference_map,
)
from src.metrics import (
    compute_changed_components,
    compute_chi2_lsb,
    compute_lsb_distribution,
    compute_psnr_ssim,
)

#Параметры
SOURCE_IMAGE = "imgs/gto.png"
COVER_IMAGE = "imgs/cover.png"
PASSWORD = "ggwp"
MAIN_FILL_RATIO = 0.10
PAYLOAD_LEVELS = (0.01, 0.10)

STEGO_PLAIN = "imgs/stego_plain.png"
STEGO_ENCRYPTED = "imgs/stego_encrypted.png"
STEGO_RANDOM = "imgs/stego_random.png"
DIFF_MAP_PATH = "results/difference.png"
HISTOGRAM_PATH = "results/histogram.png"
METRICS_CSV_PATH = "results/metrics.csv"

def generate_payload_text(cover_path: str, fill_ratio: float) -> str:
    w, h = Image.open(cover_path).size
    capacity_bytes = (w * h * 3) // 8
    target_bytes = max(1, int(capacity_bytes * fill_ratio) - 48)

    base_phrase = "Анализ"
    repeats = (target_bytes // len(base_phrase)) + 1
    return (base_phrase * repeats)[:target_bytes]

def main() -> None:
    os.makedirs("results", exist_ok=True)

    shutil.copyfile(SOURCE_IMAGE, COVER_IMAGE)
    message = generate_payload_text(COVER_IMAGE, fill_ratio=MAIN_FILL_RATIO)
    print(f"Изображение: {SOURCE_IMAGE} - объём сообщения: {len(message.encode('utf-8'))} байт ({MAIN_FILL_RATIO:.0%})")

    embed_lsb_plain(COVER_IMAGE, STEGO_PLAIN, message)
    embed_lsb_encrypted(COVER_IMAGE, STEGO_ENCRYPTED, message, PASSWORD)
    embed_lsb_random(COVER_IMAGE, STEGO_RANDOM, message, PASSWORD)
    print("Сформированы файлы: cover.png, stego_plain.png, stego_encrypted.png, stego_random.png")

    stego_variants = [
        ("Plain LSB", STEGO_PLAIN),
        ("Encrypted LSB", STEGO_ENCRYPTED),
        ("Random LSB", STEGO_RANDOM),
    ]
    all_images = [("Cover", COVER_IMAGE)] + stego_variants

    #PSNR и SSIM
    print("\n--- PSNR и SSIM ---")
    print("| Вариант | PSNR (дБ) | SSIM |")
    print("|---|---:|---:|")
    for name, path in stego_variants:
        psnr, ssim = compute_psnr_ssim(COVER_IMAGE, path)
        print(f"| {name} | {psnr:.4f} | {ssim:.6f} |")

    #Подсчёт количества и доли изменённых компонент
    print("\n--- Доля изменённых компонент ---")
    print("| Вариант | Изменено компонент | Всего компонент | Changed ratio |")
    print("|---|---:|---:|---:|")
    for name, path in stego_variants:
        changed, total, ratio = compute_changed_components(COVER_IMAGE, path)
        print(f"| {name} | {changed} | {total} | {ratio:.6f} ({ratio * 100:.2f}%) |")

    #P(LSB=0) и P(LSB=1)
    print("\n--- Распределение LSB ---")
    print("| Вариант | P(LSB=0) | P(LSB=1) |")
    print("|---|---:|---:|")
    for name, path in all_images:
        p0, p1 = compute_lsb_distribution(path)
        print(f"| {name} | {p0:.6f} | {p1:.6f} |")

    #Статистический χ²-анализ
    print("\n--- χ²-анализ ---")
    print("| Вариант | χ² | p-value |")
    print("|---|---:|---:|")
    for name, path in all_images:
        chi2_val, p_val = compute_chi2_lsb(path)
        print(f"| {name} | {chi2_val:.4f} | {p_val:.6f} |")

    #Сводная таблица основного эксперимента
    print("\n--- Сводная таблица ---")
    print("| Вариант | PSNR | SSIM | Changed ratio | P(LSB=1) | χ² | p-value |")
    print("|---|---:|---:|---:|---:|---:|---:|")

    with open(METRICS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Variant", "PSNR", "SSIM", "Changed_ratio", "P_LSB_1", "Chi2", "p_value"])

        for name, path in stego_variants:
            psnr, ssim = compute_psnr_ssim(COVER_IMAGE, path)
            _, _, ch_ratio = compute_changed_components(COVER_IMAGE, path)
            _, p1 = compute_lsb_distribution(path)
            chi2_val, p_val = compute_chi2_lsb(path)

            print(
                f"| {name} | {psnr:.4f} | {ssim:.6f} | {ch_ratio:.6f} | "
                f"{p1:.6f} | {chi2_val:.4f} | {p_val:.6f} |"
            )
            writer.writerow([
                name,
                f"{psnr:.4f}",
                f"{ssim:.6f}",
                f"{ch_ratio:.6f}",
                f"{p1:.6f}",
                f"{chi2_val:.4f}",
                f"{p_val:.6f}",
            ])

    #Исследование влияния объёма данных
    print("\n--- Влияние объёма данных ---")
    print("| Payload | Вариант | PSNR (дБ) | Changed ratio | χ² | p-value |")
    print("|---:|---|---:|---:|---:|---:|")

    for ratio in PAYLOAD_LEVELS:
        msg = generate_payload_text(COVER_IMAGE, ratio)
        pct_label = f"{int(ratio * 100)}%"

        temp_cases = [
            ("Plain LSB", "imgs/_tmp_plain.png", lambda p: embed_lsb_plain(COVER_IMAGE, p, msg)),
            ("Encrypted LSB", "imgs/_tmp_enc.png", lambda p: embed_lsb_encrypted(COVER_IMAGE, p, msg, PASSWORD)),
            ("Random LSB", "imgs/_tmp_rnd.png", lambda p: embed_lsb_random(COVER_IMAGE, p, msg, PASSWORD)),
        ]

        for name, tmp_path, embed_fn in temp_cases:
            embed_fn(tmp_path)
            psnr, _ = compute_psnr_ssim(COVER_IMAGE, tmp_path)
            _, _, ch_ratio = compute_changed_components(COVER_IMAGE, tmp_path)
            chi2_val, p_val = compute_chi2_lsb(tmp_path)
            print(f"| {pct_label} | {name} | {psnr:.4f} | {ch_ratio:.6f} | {chi2_val:.2f} | {p_val:.6f} |")
            os.remove(tmp_path)

    #Визуализация: карта разности и сравнительная гистограмма
    save_difference_map(
        COVER_IMAGE,
        STEGO_PLAIN,
        STEGO_ENCRYPTED,
        STEGO_RANDOM,
        DIFF_MAP_PATH,
    )
    save_comparison_histogram(
        COVER_IMAGE,
        STEGO_PLAIN,
        STEGO_ENCRYPTED,
        STEGO_RANDOM,
        HISTOGRAM_PATH,
    )

if __name__ == "__main__":
    main()