import hashlib
import os
from pathlib import Path
from PIL import Image
from src.cipher import decrypt as xor_decrypt, encrypt as xor_encrypt
from src.aes_cipher import (
    encrypt_ecb,
    decrypt_ecb,
    encrypt_ctr,
    decrypt_ctr,
    save_metadata,
)

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def test_reversibility(
    input_path: str,
    output_dir: str,
    results_dir: str,
    secret_key: str = "strong_secret_key_2026",
) -> list[dict]:
    src_path = Path(input_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Файл не найден: {input_path}")
    img = Image.open(src_path)
    mode = img.mode
    size = img.size
    raw_pixels = img.tobytes()

    original_hash = compute_sha256(raw_pixels)
    stem = src_path.stem
    ext = ".png"

    out_dir = Path(output_dir)
    res_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    res_dir.mkdir(parents=True, exist_ok=True)

    records = []

    #Потоковый XOR
    enc_xor_bytes = xor_encrypt(raw_pixels, secret_key)
    dec_xor_bytes = xor_decrypt(enc_xor_bytes, secret_key)

    Image.frombytes(mode, size, enc_xor_bytes).save(out_dir / f"{stem}_enc_xor{ext}")
    Image.frombytes(mode, size, dec_xor_bytes).save(out_dir / f"{stem}_dec_xor{ext}")

    records.append({
        "method": "Потоковый XOR (XORShift32)",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_xor_bytes),
        "exact_match": (raw_pixels == dec_xor_bytes),
    })

    #AES-ECB
    enc_ecb_padded = encrypt_ecb(raw_pixels, secret_key)
    dec_ecb_bytes = decrypt_ecb(enc_ecb_padded, secret_key)

    enc_ecb_pixels = enc_ecb_padded[:len(raw_pixels)]
    Image.frombytes(mode, size, enc_ecb_pixels).save(out_dir / f"{stem}_enc_ecb{ext}")
    Image.frombytes(mode, size, dec_ecb_bytes).save(out_dir / f"{stem}_dec_ecb{ext}")

    records.append({
        "method": "AES-ECB",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_ecb_bytes),
        "exact_match": (raw_pixels == dec_ecb_bytes),
    })

    #AES-CTR
    nonce = os.urandom(16)
    enc_ctr_bytes, used_nonce = encrypt_ctr(raw_pixels, secret_key, nonce=nonce)
    dec_ctr_bytes = decrypt_ctr(enc_ctr_bytes, secret_key, nonce=used_nonce)

    save_metadata(
        filepath=str(res_dir / "meta.json"),
        algorithm="aes-ctr",
        source_filename=src_path.name,
        nonce=used_nonce,
    )

    Image.frombytes(mode, size, enc_ctr_bytes).save(out_dir / f"{stem}_enc_ctr{ext}")
    Image.frombytes(mode, size, dec_ctr_bytes).save(out_dir / f"{stem}_dec_ctr{ext}")

    records.append({
        "method": "AES-CTR",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_ctr_bytes),
        "exact_match": (raw_pixels == dec_ctr_bytes),
    })

    return records