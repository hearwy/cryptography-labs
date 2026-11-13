import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(key: str | bytes) -> bytes:
    if isinstance(key, bytes) and len(key) == 32:
        return key
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hashlib.sha256(key).digest()

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Unpadding не может быть пустым")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Некорректный padding PKCS#7")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Поврежденный padding PKCS#7")
    return data[:-padding_len]

def encrypt_ecb(data: bytes, key: str | bytes) -> bytes:
    aes_key = derive_key(key)
    padded = False
    if len(data) % 16 != 0:
        data = pad_pkcs7(data, block_size=16)
        padded = True
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt_ecb(data: bytes, key: str | bytes, is_padded: bool = False) -> bytes:
    aes_key = derive_key(key)
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    if is_padded:
        return unpad_pkcs7(decrypted)
    return decrypted

def encrypt_ctr(data: bytes, key: str | bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    aes_key = derive_key(key)
    if nonce is None:
        nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, nonce

def decrypt_ctr(data: bytes, key: str | bytes, nonce: bytes) -> bytes:
    aes_key = derive_key(key)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def save_metadata(
    filepath: str,
    algorithm: str,
    source_filename: str,
    nonce: bytes | None = None,
    tail: bytes | None = None,
) -> None:
    path = Path(filepath)
    meta = {}
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except json.JSONDecodeError:
            meta = {}

    meta["algorithm"] = algorithm
    meta["source"] = source_filename
    if nonce is not None:
        meta["nonce"] = nonce.hex()
    if tail is not None:
        meta["ecb_tail"] = tail.hex()
    else:
        meta.pop("ecb_tail", None)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

def load_metadata(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "nonce" in data and data["nonce"]:
        data["nonce_bytes"] = bytes.fromhex(data["nonce"])
    if "ecb_tail" in data and data["ecb_tail"]:
        data["tail_bytes"] = bytes.fromhex(data["ecb_tail"])
    return data