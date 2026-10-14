"""
Low-level cryptographic primitives. All crypto goes through this module.

  * KDF:  Argon2id (argon2-cffi) - master password -> key-encryption key (KEK)
  * AEAD: AES-256-GCM (pyca/cryptography) - everything else
  * RNG:  os.urandom / secrets (OS CSPRNG)
"""
import ctypes
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

DEFAULT_KDF = {"t": 3, "m": 65536, "p": 4}      # m in KiB -> 64 MiB
MIN_KDF = {"t": 2, "m": 19456, "p": 1}          # OWASP minimum for Argon2id

try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    _mlock = _libc.mlock
    _munlock = _libc.munlock
except OSError:
    _mlock = None
    _munlock = None


def _lock_memory(buf: bytearray) -> bool:
    if _mlock is None or len(buf) == 0:
        return False
    addr = (ctypes.c_char * len(buf)).from_buffer(buf)
    return _mlock(ctypes.addressof(addr), len(buf)) == 0


def _unlock_memory(buf: bytearray) -> None:
    if _munlock is None or len(buf) == 0:
        return
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        _munlock(ctypes.addressof(addr), len(buf))
    except (ValueError, BufferError):
        pass


class SecureBuffer:
    """Context manager that holds key material in a bytearray, mlocks it,
    and wipes + munlocks on exit."""

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        _lock_memory(self._buf)

    @property
    def buf(self) -> bytearray:
        return self._buf

    def __enter__(self):
        return self._buf

    def __exit__(self, *exc):
        self.close()

    def close(self):
        wipe(self._buf)
        _unlock_memory(self._buf)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def derive_kek(password: str, salt: bytes, t: int, m: int, p: int) -> bytearray:
    raw = hash_secret_raw(password.encode("utf-8"), salt, time_cost=t,
                          memory_cost=m, parallelism=p, hash_len=KEY_SIZE, type=Type.ID)
    return bytearray(raw)


def seal(key, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)


def open_(key, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and verify. Raises InvalidTag on any modification."""
    return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)


def wipe(buf: bytearray) -> None:
    """Best-effort zeroing of key material (see README: Python limitations)."""
    for i in range(len(buf)):
        buf[i] = 0


__all__ = ["InvalidTag", "derive_kek", "seal", "open_", "wipe", "random_bytes",
           "SecureBuffer", "KEY_SIZE", "NONCE_SIZE", "TAG_SIZE", "DEFAULT_KDF", "MIN_KDF"]
