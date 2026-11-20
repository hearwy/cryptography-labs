import csv
import os
import shutil

from PIL import Image

from src.lsb import (
    embed_lsb_encrypted,
    embed_lsb_plain,
    embed_lsb_random,
    extract_lsb_encrypted,
    extract_lsb_plain,
    extract_lsb_random,
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

# Параметры эксперимента
IMAGES_TO_COMPARE = [
    ("gto.png", "imgs/gto.png", True),
    ("gradient.png", "imgs/gradient.png", False),
]
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

# 4 байта заголовка длины + 16 байт salt + 12 байт nonce + 16 байт GCM
CRYPTO_OVERHEAD_BYTES = 48

def generate_payload_text(cover_path: str, fill_ratio: float) -> str:
    w, h = Image.open(cover_path).size
    capacity_bytes = (w * h * 3) // 8
    target_bytes = max(1, int(capacity_bytes * fill_ratio) - CRYPTO_OVERHEAD_BYTES)

    base_phrase = "hrumki"
    base_bytes = base_phrase.encode("utf-8")
    repeats = (target_bytes // len(base_bytes)) + 1
    payload_bytes = (base_bytes * repeats)[:target_bytes]
    return payload_bytes.decode("utf-8")

def run_experiment_for_image(
    image_label: str,
    source_path: str,
    save_artifacts: bool,
) -> tuple[list[list[str]], list[dict]]:
    w, h = Image.open(source_path).size
    capacity_bytes = (w * h * 3) // 8

    if save_artifacts:
        cover_path = COVER_IMAGE
        plain_path = STEGO_PLAIN
        enc_path = STEGO_ENCRYPTED
        rnd_path = STEGO_RANDOM
        shutil.copyfile(source_path, cover_path)
    else:
        cover_path = source_path
        plain_path = "imgs/_tmp_cmp_plain.png"
        enc_path = "imgs/_tmp_cmp_enc.png"
        rnd_path = "imgs/_tmp_cmp_rnd.png"

    message = generate_payload_text(cover_path, fill_ratio=MAIN_FILL_RATIO)
    msg_bytes = len(message.encode("utf-8"))
    actual_ratio = (msg_bytes + CRYPTO_OVERHEAD_BYTES) / capacity_bytes
    print(
        f"\n================ {image_label} ({w}x{h}) ================\n"
        f"Объём сообщения: {msg_bytes} байт "
        f"(с заголовками: {msg_bytes + CRYPTO_OVERHEAD_BYTES} / {capacity_bytes} байт)"
    )

    embed_lsb_plain(cover_path, plain_path, message)
    embed_lsb_encrypted(cover_path, enc_path, message, PASSWORD)
    embed_lsb_random(cover_path, rnd_path, message, PASSWORD)

    # Проверка корректности извлечения и расшифрования
    assert extract_lsb_plain(plain_path) == message, "Ошибка извлечения Plain LSB"
    assert extract_lsb_encrypted(enc_path, PASSWORD) == message, "Ошибка извлечения Encrypted LSB"
    assert extract_lsb_random(rnd_path, PASSWORD) == message, "Ошибка извлечения Random LSB"

    if save_artifacts:
        print("Сформированы файлы: cover.png, stego_plain.png, stego_encrypted.png, stego_random.png")

    stego_variants = [
        ("Plain LSB", plain_path),
        ("Encrypted LSB", enc_path),
        ("Encrypted Random LSB", rnd_path),
    ]
    all_images = [("Cover", cover_path)] + stego_variants

    # PSNR и SSIM
    print("\n--- PSNR и SSIM ---")
    print("| Вариант | PSNR (дБ) | SSIM |")
    print("|---|---:|---:|")
    for name, path in stego_variants:
        psnr, ssim = compute_psnr_ssim(cover_path, path)
        print(f"| {name} | {psnr:.4f} | {ssim:.6f} |")

    # Подсчёт количества и доли изменённых компонент
    print("\n--- Доля изменённых компонент ---")
    print("| Вариант | Изменено компонент | Всего компонент | Changed ratio |")
    print("|---|---:|---:|---:|")
    for name, path in stego_variants:
        changed, total, ratio = compute_changed_components(cover_path, path)
        print(f"| {name} | {changed} | {total} | {ratio:.6f} ({ratio * 100:.2f}%) |")

    # P(LSB=0) и P(LSB=1)
    print("\n--- Распределение LSB ---")
    print("| Вариант | P(LSB=0) | P(LSB=1) |")
    print("|---|---:|---:|")
    cover_p0, cover_p1 = 0.0, 0.0
    for name, path in all_images:
        p0, p1 = compute_lsb_distribution(path)
        if name == "Cover":
            cover_p0, cover_p1 = p0, p1
        print(f"| {name} | {p0:.6f} | {p1:.6f} |")

    # Статистический χ²-анализ
    print("\n--- χ²-анализ ---")
    print("| Вариант | χ² | p-value |")
    print("|---|---:|---:|")
    cover_chi2, cover_pval = 0.0, 0.0
    for name, path in all_images:
        chi2_val, p_val = compute_chi2_lsb(path)
        if name == "Cover":
            cover_chi2, cover_pval = chi2_val, p_val
        print(f"| {name} | {chi2_val:.4f} | {p_val:.6f} |")

    # Сводная таблица по изображению
    main_pct_label = f"{int(MAIN_FILL_RATIO * 100)}%"
    print(f"\n--- Сводная таблица ({image_label}) ---")
    print("| Вариант | PSNR | SSIM | Изменено компонент | Changed ratio | P(LSB=0) | P(LSB=1) | χ² | p-value |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    print(
        f"| Cover | — | — | 0 | 0.000000 | "
        f"{cover_p0:.6f} | {cover_p1:.6f} | {cover_chi2:.4f} | {cover_pval:.6f} |"
    )

    csv_rows: list[list[str]] = [
        [
            image_label,
            "0%",
            "Cover",
            "",
            "",
            "0",
            "0.000000",
            f"{cover_p0:.6f}",
            f"{cover_p1:.6f}",
            f"{cover_chi2:.4f}",
            f"{cover_pval:.6f}",
            "",
            "",
        ]
    ]
    comparison_rows: list[dict] = []
    main_variant_metrics: dict[str, tuple[float, float, float, float]] = {}

    for name, path in stego_variants:
        psnr, ssim = compute_psnr_ssim(cover_path, path)
        changed, _, ch_ratio = compute_changed_components(cover_path, path)
        p0, p1 = compute_lsb_distribution(path)
        chi2_val, p_val = compute_chi2_lsb(path)

        delta_p1 = p1 - cover_p1
        delta_chi2_pct = ((chi2_val - cover_chi2) / cover_chi2) * 100.0 if cover_chi2 else 0.0

        print(
            f"| {name} | {psnr:.4f} | {ssim:.6f} | {changed} | {ch_ratio:.6f} | "
            f"{p0:.6f} | {p1:.6f} | {chi2_val:.4f} | {p_val:.6f} |"
        )
        csv_rows.append([
            image_label,
            main_pct_label,
            name,
            f"{psnr:.4f}",
            f"{ssim:.6f}",
            str(changed),
            f"{ch_ratio:.6f}",
            f"{p0:.6f}",
            f"{p1:.6f}",
            f"{chi2_val:.4f}",
            f"{p_val:.6f}",
            f"{delta_p1:+.6f}",
            f"{delta_chi2_pct:+.1f}%",
        ])

        main_variant_metrics[name] = (psnr, ch_ratio, chi2_val, p_val)
        comparison_rows.append({
            "image": image_label,
            "variant": name,
            "psnr": psnr,
            "ssim": ssim,
            "changed_ratio": ch_ratio,
            "delta_p1": delta_p1,
            "delta_chi2_pct": delta_chi2_pct,
        })

    if save_artifacts:
        print(f"\n--- Влияние объёма данных ({image_label}) ---")
        print("| Payload | Вариант | PSNR (дБ) | Changed ratio | χ² | p-value |")
        print("|---:|---|---:|---:|---:|---:|")

        for ratio in PAYLOAD_LEVELS:
            pct_label = f"{int(ratio * 100)}%"
            if ratio == MAIN_FILL_RATIO:
                for name, _ in stego_variants:
                    psnr, ch_ratio, chi2_val, p_val = main_variant_metrics[name]
                    print(f"| {pct_label} | {name} | {psnr:.4f} | {ch_ratio:.6f} | {chi2_val:.2f} | {p_val:.6f} |")
                continue

            msg = generate_payload_text(cover_path, ratio)
            temp_cases = [
                ("Plain LSB", "imgs/_tmp_plain.png", lambda p: embed_lsb_plain(cover_path, p, msg)),
                ("Encrypted LSB", "imgs/_tmp_enc.png", lambda p: embed_lsb_encrypted(cover_path, p, msg, PASSWORD)),
                ("Encrypted Random LSB", "imgs/_tmp_rnd.png", lambda p: embed_lsb_random(cover_path, p, msg, PASSWORD)),
            ]

            for name, tmp_path, embed_fn in temp_cases:
                embed_fn(tmp_path)
                psnr, ssim = compute_psnr_ssim(cover_path, tmp_path)
                changed, _, ch_ratio = compute_changed_components(cover_path, tmp_path)
                p0, p1 = compute_lsb_distribution(tmp_path)
                chi2_val, p_val = compute_chi2_lsb(tmp_path)
                delta_p1 = p1 - cover_p1
                delta_chi2_pct = ((chi2_val - cover_chi2) / cover_chi2) * 100.0 if cover_chi2 else 0.0

                print(f"| {pct_label} | {name} | {psnr:.4f} | {ch_ratio:.6f} | {chi2_val:.2f} | {p_val:.6f} |")
                csv_rows.append([
                    image_label,
                    pct_label,
                    name,
                    f"{psnr:.4f}",
                    f"{ssim:.6f}",
                    str(changed),
                    f"{ch_ratio:.6f}",
                    f"{p0:.6f}",
                    f"{p1:.6f}",
                    f"{chi2_val:.4f}",
                    f"{p_val:.6f}",
                    f"{delta_p1:+.6f}",
                    f"{delta_chi2_pct:+.1f}%",
                ])
                os.remove(tmp_path)

        # Карта разности и сравнительная гистограмма
        save_difference_map(
            cover_path,
            plain_path,
            enc_path,
            rnd_path,
            DIFF_MAP_PATH,
        )
        save_comparison_histogram(
            cover_path,
            plain_path,
            enc_path,
            rnd_path,
            HISTOGRAM_PATH,
        )
    else:
        for tmp_path in (plain_path, enc_path, rnd_path):
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    return csv_rows, comparison_rows


def main() -> None:
    os.makedirs("results", exist_ok=True)

    all_csv_rows: list[list[str]] = []
    all_comparison_rows: list[dict] = []
    for image_label, source_path, save_artifacts in IMAGES_TO_COMPARE:
        rows, cmp_rows = run_experiment_for_image(image_label, source_path, save_artifacts)
        all_csv_rows.extend(rows)
        all_comparison_rows.extend(cmp_rows)

    print(f"\n--- Сравнение изображений разного типа ({int(MAIN_FILL_RATIO * 100)}%) ---")
    print("| Изображение | Вариант | PSNR (дБ) | SSIM | Changed ratio | Смещение P(LSB=1) от Cover | Изменение χ² от Cover |")
    print("|---|---|---:|---:|---:|---:|---:|")
    for row in all_comparison_rows:
        print(
            f"| {row['image']} | {row['variant']} | {row['psnr']:.4f} | {row['ssim']:.6f} | "
            f"{row['changed_ratio'] * 100:.2f}% | {row['delta_p1']:+.6f} | {row['delta_chi2_pct']:+.1f}% |"
        )

    with open(METRICS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "Image",
            "Payload",
            "Variant",
            "PSNR",
            "SSIM",
            "Changed_components",
            "Changed_ratio",
            "P_LSB_0",
            "P_LSB_1",
            "Chi2",
            "p_value",
            "Delta_P_LSB_1",
            "Delta_Chi2",
        ])
        writer.writerows(all_csv_rows)

    print(f"\nСводные метрики сохранены в {METRICS_CSV_PATH}")

if __name__ == "__main__":
    main()