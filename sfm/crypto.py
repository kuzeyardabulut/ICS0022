"""
Low-level cryptographic primitives. All crypto goes through this module.

  * KDF:  Argon2id (argon2-cffi) - master password -> key-encryption key (KEK)
  * AEAD: AES-256-GCM (pyca/cryptography) - everything else
  * RNG:  os.urandom / secrets (OS CSPRNG)
"""
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

# Default Argon2id cost (~0.5 s on a laptop). Minimums are enforced when a
# keystore is loaded so an attacker cannot downgrade them by editing the file.
DEFAULT_KDF = {"t": 3, "m": 65536, "p": 4}      # m in KiB -> 64 MiB
MIN_KDF = {"t": 2, "m": 19456, "p": 1}          # OWASP minimum for Argon2id


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
           "KEY_SIZE", "NONCE_SIZE", "TAG_SIZE", "DEFAULT_KDF", "MIN_KDF"]
