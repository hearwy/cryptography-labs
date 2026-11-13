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
    load_metadata,
)

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def test_reversibility(
    input_path: str,
    output_dir: str,
    results_dir: str,
    secret_key: str = "ggwp",
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
    enc_xor_path = out_dir / f"{stem}_enc_xor{ext}"
    dec_xor_path = out_dir / f"{stem}_dec_xor{ext}"

    enc_xor_bytes = xor_encrypt(raw_pixels, secret_key)
    Image.frombytes(mode, size, enc_xor_bytes).save(enc_xor_path)

    loaded_xor_bytes = Image.open(enc_xor_path).tobytes()
    dec_xor_bytes = xor_decrypt(loaded_xor_bytes, secret_key)
    Image.frombytes(mode, size, dec_xor_bytes).save(dec_xor_path)

    records.append({
        "method": "Потоковый XOR (XORShift32)",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_xor_bytes),
        "exact_match": (raw_pixels == dec_xor_bytes),
    })

    meta_path = str(res_dir / "meta.json")

    #AES-ECB
    enc_ecb_path = out_dir / f"{stem}_enc_ecb{ext}"
    dec_ecb_path = out_dir / f"{stem}_dec_ecb{ext}"

    enc_ecb_full = encrypt_ecb(raw_pixels, secret_key)
    is_padded = len(raw_pixels) % 16 != 0
    tail = enc_ecb_full[len(raw_pixels):] if is_padded else None

    Image.frombytes(mode, size, enc_ecb_full[:len(raw_pixels)]).save(enc_ecb_path)
    save_metadata(meta_path, "aes-ecb", src_path.name, tail=tail)

    loaded_ecb_pixels = Image.open(enc_ecb_path).tobytes()
    ecb_meta = load_metadata(meta_path)
    full_ciphertext = loaded_ecb_pixels + ecb_meta.get("tail_bytes", b"")
    dec_ecb_bytes = decrypt_ecb(full_ciphertext, secret_key, is_padded=is_padded)
    Image.frombytes(mode, size, dec_ecb_bytes).save(dec_ecb_path)

    records.append({
        "method": "AES-ECB",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_ecb_bytes),
        "exact_match": (raw_pixels == dec_ecb_bytes),
    })

    #AES-CTR
    enc_ctr_path = out_dir / f"{stem}_enc_ctr{ext}"
    dec_ctr_path = out_dir / f"{stem}_dec_ctr{ext}"

    nonce = os.urandom(16)
    enc_ctr_bytes, used_nonce = encrypt_ctr(raw_pixels, secret_key, nonce=nonce)
    Image.frombytes(mode, size, enc_ctr_bytes).save(enc_ctr_path)
    save_metadata(meta_path, "aes-ctr", src_path.name, nonce=used_nonce)

    loaded_ctr_bytes = Image.open(enc_ctr_path).tobytes()
    ctr_meta = load_metadata(meta_path)
    dec_ctr_bytes = decrypt_ctr(loaded_ctr_bytes, secret_key, nonce=ctr_meta["nonce_bytes"])
    Image.frombytes(mode, size, dec_ctr_bytes).save(dec_ctr_path)

    records.append({
        "method": "AES-CTR",
        "original_sha256": original_hash,
        "restored_sha256": compute_sha256(dec_ctr_bytes),
        "exact_match": (raw_pixels == dec_ctr_bytes),
    })

    return records