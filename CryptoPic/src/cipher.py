import hashlib
from typing import Iterator

class XORShift32:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF
        if self.state == 0:
            self.state = 0x6D2B79F5

    def next_u32(self) -> int:
        x = self.state
        x = (x ^ (x << 13)) & 0xFFFFFFFF
        x = (x ^ (x >> 17)) & 0xFFFFFFFF
        x = (x ^ (x << 5)) & 0xFFFFFFFF
        self.state = x
        return x

    def byte_stream(self) -> Iterator[int]:
        while True:
            word = self.next_u32()
            yield word & 0xFF
            yield (word >> 8) & 0xFF
            yield (word >> 16) & 0xFF
            yield (word >> 24) & 0xFF

def derive_seed(key: str | bytes) -> int:
    if isinstance(key, str):
        key = key.encode("utf-8")
    digest = hashlib.sha256(key).digest()
    seed = int.from_bytes(digest[:4], byteorder="big")
    return seed if seed != 0 else 0x12345678

def xor_cipher(data: bytes, key: str | bytes) -> bytes:
    seed = derive_seed(key)
    prng = XORShift32(seed)
    keystream = prng.byte_stream()
    return bytes(b ^ next(keystream) for b in data)

encrypt = xor_cipher
decrypt = xor_cipher