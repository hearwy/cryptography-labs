import struct
import numpy as np
from PIL import Image
from src.crypto import decrypt_message, encrypt_message, get_permutation_indices

HEADER_SIZE_BYTES = 4
HEADER_SIZE_BITS = 32
CLEAR_LSB_MASK = 0xFE
EXTRACT_LSB_MASK = 1

def bytes_to_bits(data: bytes) -> np.ndarray:
    byte_array = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(byte_array)

def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def embed_bytes_sequential(cover_path: str, stego_path: str, data: bytes) -> None:
    payload = struct.pack(">I", len(data)) + data

    bits = bytes_to_bits(payload)
    total_bits = len(bits)

    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.ravel()

    if total_bits > flat.size:
        raise ValueError(
            f"Слишком большие данные"
        )

    flat[:total_bits] = (flat[:total_bits] & CLEAR_LSB_MASK) | bits

    stego_arr = flat.reshape(arr.shape)
    Image.fromarray(stego_arr, mode="RGB").save(stego_path, format="PNG")


def extract_bytes_sequential(stego_path: str) -> bytes:
    img = Image.open(stego_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).ravel()

    if flat.size < HEADER_SIZE_BITS:
        raise ValueError("Изображение слишком маленькое")

    header_bits = flat[:HEADER_SIZE_BITS] & EXTRACT_LSB_MASK
    header_bytes = bits_to_bytes(header_bits)
    (data_len,) = struct.unpack(">I", header_bytes)

    total_bits = HEADER_SIZE_BITS + data_len * 8
    if total_bits > flat.size:
        raise ValueError(f"Некорректная длина в заголовке")

    data_bits = flat[HEADER_SIZE_BITS:total_bits] & EXTRACT_LSB_MASK
    return bits_to_bytes(data_bits)

#Plain LSB
def embed_lsb_plain(cover_path: str, stego_path: str, message: str) -> None:
    embed_bytes_sequential(cover_path, stego_path, message.encode("utf-8"))

def extract_lsb_plain(stego_path: str) -> str:
    raw_bytes = extract_bytes_sequential(stego_path)
    return raw_bytes.decode("utf-8")


#Encrypted LSB
def embed_lsb_encrypted(cover_path: str, stego_path: str, message: str, password: str) -> None:
    encrypted_blob = encrypt_message(message, password)
    embed_bytes_sequential(cover_path, stego_path, encrypted_blob)

def extract_lsb_encrypted(stego_path: str, password: str) -> str:
    encrypted_blob = extract_bytes_sequential(stego_path)
    return decrypt_message(encrypted_blob, password)


#Encrypted Random LSB
def embed_lsb_random(cover_path: str, stego_path: str, message: str, password: str) -> None:
    encrypted_blob = encrypt_message(message, password)
    payload = struct.pack(">I", len(encrypted_blob)) + encrypted_blob
    bits = bytes_to_bits(payload)
    total_bits = len(bits)

    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.ravel()

    if total_bits > flat.size:
        raise ValueError(
            f"Данные слишком большие"
        )

    indices = get_permutation_indices(flat.size, password)
    target_indices = indices[:total_bits]

    flat[target_indices] = (flat[target_indices] & CLEAR_LSB_MASK) | bits

    stego_arr = flat.reshape(arr.shape)
    Image.fromarray(stego_arr, mode="RGB").save(stego_path, format="PNG")

def extract_lsb_random(stego_path: str, password: str) -> str:
    img = Image.open(stego_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).ravel()

    if flat.size < HEADER_SIZE_BITS:
        raise ValueError("Изображение слишком маленькое")

    indices = get_permutation_indices(flat.size, password)

    header_bits = flat[indices[:HEADER_SIZE_BITS]] & EXTRACT_LSB_MASK
    header_bytes = bits_to_bytes(header_bits)
    (data_len,) = struct.unpack(">I", header_bytes)

    total_bits = HEADER_SIZE_BITS + data_len * 8
    if total_bits > flat.size:
        raise ValueError(f"Некорректная длина в заголовке или неверный пароль.")

    encrypted_bits = flat[indices[HEADER_SIZE_BITS:total_bits]] & EXTRACT_LSB_MASK
    encrypted_blob = bits_to_bytes(encrypted_bits)
    return decrypt_message(encrypted_blob, password)