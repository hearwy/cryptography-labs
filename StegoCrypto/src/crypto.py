import hashlib
import os
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
GCM_TAG_SIZE = 16
PBKDF2_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_message(message: str, password: str) -> bytes:
    #Генерация соли и nonce
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    #Получение ключа шифрования из пароля и сгенерированной соли
    key = derive_key(password, salt)

    #Шифрование текста
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=message.encode("utf-8"),
        associated_data=None,
    )

    #Соль + nonce + шифротекст
    return salt + nonce + ciphertext

def decrypt_message(encrypted_blob: bytes, password: str) -> str:
    #Минимальный размер пакета: соль + nonce + тег
    min_size = SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE
    if len(encrypted_blob) < min_size:
        raise ValueError("Данные повреждены или неполные, так как слишком короткий зашифрованный пакет")

    #Извлечение из байтового пакета соль, nonce и шифротекст
    salt = encrypted_blob[:SALT_SIZE]
    nonce = encrypted_blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_blob[SALT_SIZE + NONCE_SIZE :]

    #Восстановление того же самого ключа по паролю и извлечённой соли
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    #Расшифровка данных и проверка тега аутентификации
    try:
        plaintext_bytes = aesgcm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None,
        )
    except Exception as exc:
        # Исключение возникает, если пароль неверный или пиксели изображения были изменены
        raise ValueError("Неверный пароль или повреждённые данные при расшифровке") from exc

    return plaintext_bytes.decode("utf-8")

def get_permutation_indices(total_elements: int, password: str) -> np.ndarray:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    seed = int.from_bytes(digest[:8], byteorder="big", signed=False)
    rng = np.random.default_rng(seed)
    return rng.permutation(total_elements)