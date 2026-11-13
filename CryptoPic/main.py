import argparse
import csv
import json
import os
import sys
from pathlib import Path
from PIL import Image

from src.cipher import encrypt as xor_encrypt, decrypt as xor_decrypt
from src.aes_cipher import (
    encrypt_ecb,
    decrypt_ecb,
    encrypt_ctr,
    decrypt_ctr,
    save_metadata,
    load_metadata,
)
from src.metrics import analyze_all, run_key_sensitivity_test
from src.verify import test_reversibility

def run_meta_pipeline(meta_path: str, secret_key: str = "ggwp") -> None:
    path_obj = Path(meta_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Файл конфигурации не найден: {meta_path}")

    with open(path_obj, "r", encoding="utf-8") as f:
        meta = json.load(f)

    algorithm = meta.get("algorithm", "aes-ctr").lower()
    source_path = meta.get("source")
    nonce_hex = meta.get("nonce") or meta.get("iv")
    path_encrypted = meta.get("pathEncrypted")
    path_decrypted = meta.get("pathDecrypted")

    if not source_path or not Path(source_path).exists():
        raise FileNotFoundError(f"Исходный файл не найден: {source_path}")

    img = Image.open(source_path)
    mode, size = img.mode, img.size
    raw_pixels = img.tobytes()

    print(f"Обработка файла: {source_path}")
    print(f"Выбранный алгоритм: {algorithm}")

    enc_bytes = None
    dec_bytes = None

    if algorithm in ["thread", "xor"]:
        enc_bytes = xor_encrypt(raw_pixels, secret_key)
        dec_bytes = xor_decrypt(enc_bytes, secret_key)


    elif algorithm == "aes-ecb":
        enc_full = encrypt_ecb(raw_pixels, secret_key)
        is_padded = len(raw_pixels) % 16 != 0
        tail = enc_full[len(raw_pixels):] if is_padded else None
        if tail is not None:
            meta["ecb_tail"] = tail.hex()
            with open(path_obj, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
        enc_bytes = enc_full[:len(raw_pixels)]
        dec_bytes = decrypt_ecb(enc_full, secret_key, is_padded=is_padded)

    elif algorithm in ["aes-ctr", "ctr"]:
        if nonce_hex:
            nonce = bytes.fromhex(nonce_hex)
        else:
            nonce = os.urandom(16)
            meta["nonce"] = nonce.hex()
            with open(path_obj, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
            print(f"Сгенерирован и сохранён новый nonce: {nonce.hex()}")

        enc_bytes, _ = encrypt_ctr(raw_pixels, secret_key, nonce=nonce)
        dec_bytes = decrypt_ctr(enc_bytes, secret_key, nonce=nonce)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    if path_encrypted and enc_bytes:
        Path(path_encrypted).parent.mkdir(parents=True, exist_ok=True)
        Image.frombytes(mode, size, enc_bytes).save(path_encrypted)
        print(f"Зашифрованное изображение сохранено: {path_encrypted}")

    if path_decrypted and dec_bytes:
        Path(path_decrypted).parent.mkdir(parents=True, exist_ok=True)
        Image.frombytes(mode, size, dec_bytes).save(path_decrypted)
        print(f"Расшифрованное изображение сохранено: {path_decrypted}")

    print(f"Обратимость подтверждена: {raw_pixels == dec_bytes}")


def main():
    if len(sys.argv) == 2 and sys.argv[1].endswith(".json"):
        run_meta_pipeline(sys.argv[1])
        return

    parser = argparse.ArgumentParser(description="Шифрование и статистический анализ изображений")
    parser.add_argument(
        "action",
        nargs="?",
        choices=["encrypt", "decrypt", "test"],
        default="test",
        help="Действие: encrypt, decrypt или test (по умолчанию: test)",
    )
    parser.add_argument(
        "-i", "--input",
        default="imgs/gradient.png",
        help="Путь к любому входному изображению (например, imgs/checkerboard.png, imgs/gradient.png, imgs/pikachu.png)",
    )
    parser.add_argument("-o", "--output", default="imgs/output.png", help="Путь к выходному файлу")
    parser.add_argument(
        "-a", "--algo",
        choices=["xor", "ecb", "ctr"],
        default="ctr",
        help="Алгоритм шифрования: xor, ecb или ctr",
    )
    parser.add_argument("-k", "--key", default="ggwp", help="Секретный ключ")
    parser.add_argument("-m", "--meta", default="results/meta.json", help="Файл параметров nonce/iv")

    args = parser.parse_args()

    if args.action == "encrypt":
        img = Image.open(args.input)
        raw_pixels = img.tobytes()
        mode, size = img.mode, img.size

        if args.algo == "xor":
            enc_data = xor_encrypt(raw_pixels, args.key)
        elif args.algo == "ecb":
            enc_full = encrypt_ecb(raw_pixels, args.key)
            tail = enc_full[len(raw_pixels):] if len(raw_pixels) % 16 != 0 else None
            save_metadata(args.meta, "aes-ecb", Path(args.input).name, tail=tail)
            enc_data = enc_full[:len(raw_pixels)]
        elif args.algo == "ctr":
            enc_data, nonce = encrypt_ctr(raw_pixels, args.key)
            save_metadata(args.meta, "aes-ctr", Path(args.input).name, nonce=nonce)
            print(f"Параметры шифрования (nonce) записаны в {args.meta}")

        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Image.frombytes(mode, size, enc_data).save(args.output)
        print(f"Файл {args.input} успешно зашифрован [{args.algo}] -> {args.output}")

    elif args.action == "decrypt":
        img = Image.open(args.input)
        raw_pixels = img.tobytes()
        mode, size = img.mode, img.size

        if args.algo == "xor":
            dec_data = xor_decrypt(raw_pixels, args.key)
        elif args.algo == "ecb":
            meta = load_metadata(args.meta)
            tail = meta.get("tail_bytes", b"")
            is_padded = len(tail) > 0
            dec_data = decrypt_ecb(raw_pixels + tail, args.key, is_padded=is_padded)
        elif args.algo == "ctr":
            meta = load_metadata(args.meta)
            dec_data = decrypt_ctr(raw_pixels, args.key, nonce=meta["nonce_bytes"])

        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Image.frombytes(mode, size, dec_data).save(args.output)
        print(f"Файл {args.input} успешно расшифрован [{args.algo}] -> {args.output}")

    elif args.action == "test":
        target_image = args.input
        output_dir = "imgs"
        results_dir = "results"
        secret_key = args.key

        print(f"Полный статистический анализ для: {target_image}")
        print("\n1. Проверка обратимости шифрования")
        reversibility_results = test_reversibility(
            input_path=target_image,
            output_dir=output_dir,
            results_dir=results_dir,
            secret_key=secret_key,
        )
        for r in reversibility_results:
            print(f"[{'OK' if r['exact_match'] else 'FAIL'}] {r['method']}: SHA-256 = {r['restored_sha256']}")

        print("\n2. Расчет метрик и генерация гистограмм")
        metrics = analyze_all(
            image_path=target_image,
            results_dir=results_dir,
            secret_key=secret_key,
        )

        csv_path = Path(results_dir) / "metrics.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Метод", "Энтропия", "Corr H", "Corr V"])
            writer.writeheader()
            writer.writerows(metrics)

        for row in metrics:
            print(f"  {row['Метод']:<24} | H: {row['Энтропия']} | Corr H: {row['Corr H']} | Corr V: {row['Corr V']}")

        print("\n3. Тест чувствительности к ключу (NPCR / UACI)")
        raw_bytes = Image.open(target_image).tobytes()
        key_test = run_key_sensitivity_test(raw_bytes, base_key=secret_key)
        print(f"  {key_test['method']}: NPCR = {key_test['NPCR']:.4f}%, UACI = {key_test['UACI']:.4f}%")

main()