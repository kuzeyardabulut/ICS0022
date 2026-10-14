"""
Keystore: holds the random 256-bit master key (MK), wrapped with a KEK that is
derived from the master password with Argon2id.

keystore.json
  {"version": 1,
   "kdf":  {"alg": "argon2id", "salt": b64, "t": 3, "m": 65536, "p": 4},
   "wrap": {"nonce": b64, "ct": b64}}      # AES-256-GCM(KEK, MK)

The version and KDF parameters are authenticated as associated data, so editing
them makes unwrapping fail. Authentication = successfully unwrapping the MK;
no password hash is stored separately.
"""
import base64
import json
import logging
import os
from pathlib import Path

from . import audit, crypto
from .errors import AuthError, SFMError
from .fileio import atomic_write_bytes

VERSION = 1


def default_path() -> Path:
    home = os.environ.get("SFM_HOME")
    base = Path(home) if home else Path.home() / ".config" / "sfm"
    return base / "keystore.json"


def _b64e(b): return base64.b64encode(b).decode()
def _b64d(s): return base64.b64decode(s, validate=True)


def _aad(kdf: dict) -> bytes:
    return json.dumps({"version": VERSION, "kdf": kdf}, sort_keys=True).encode()


def _check_keystore_owner(path: Path) -> None:
    try:
        st = path.stat()
        if st.st_uid != os.getuid():
            raise SFMError("access denied: you do not own this keystore")
    except FileNotFoundError:
        pass


def create(path: Path, password: str, kdf_params=None) -> None:
    if path.exists():
        raise SFMError(f"keystore already exists at {path}")
    params = dict(kdf_params or crypto.DEFAULT_KDF)
    kdf = {"alg": "argon2id", "salt": _b64e(crypto.random_bytes(16)), **params}
    mk = bytearray(crypto.random_bytes(crypto.KEY_SIZE))
    _write(path, kdf, mk, password)
    crypto.wipe(mk)


def _write(path: Path, kdf: dict, mk: bytearray, password: str) -> None:
    kek = crypto.derive_kek(password, _b64d(kdf["salt"]), kdf["t"], kdf["m"], kdf["p"])
    nonce = crypto.random_bytes(crypto.NONCE_SIZE)
    ct = crypto.seal(kek, nonce, bytes(mk), _aad(kdf))
    crypto.wipe(kek)
    doc = {"version": VERSION, "kdf": kdf, "wrap": {"nonce": _b64e(nonce), "ct": _b64e(ct)}}
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write_bytes(path, json.dumps(doc, indent=2).encode(), overwrite=True)


def _load(path: Path) -> dict:
    _check_keystore_owner(path)
    try:
        doc = json.loads(path.read_text())
        kdf = doc["kdf"]
        if doc["version"] != VERSION or kdf["alg"] != "argon2id":
            raise ValueError
        for k, minimum in crypto.MIN_KDF.items():
            if int(kdf[k]) < minimum:
                raise SFMError("keystore KDF parameters are below the allowed minimum")
        return doc
    except FileNotFoundError:
        raise SFMError("no keystore found - run 'sfm init' first") from None
    except SFMError:
        raise
    except Exception:
        raise SFMError("keystore file is malformed") from None


def unlock(path: Path, password: str) -> bytearray:
    """Return the master key, or raise AuthError."""
    doc = _load(path)
    kdf = doc["kdf"]
    kek = crypto.derive_kek(password, _b64d(kdf["salt"]), kdf["t"], kdf["m"], kdf["p"])
    try:
        mk = crypto.open_(kek, _b64d(doc["wrap"]["nonce"]), _b64d(doc["wrap"]["ct"]), _aad(kdf))
    except crypto.InvalidTag:
        audit.log_event("auth_failed", level=logging.WARNING,
                        reason="wrong master password or keystore was modified")
        raise AuthError("wrong master password or keystore was modified") from None
    finally:
        crypto.wipe(kek)
    return bytearray(mk)


def change_password(path: Path, old: str, new: str) -> None:
    """Re-wrap the same master key: no file needs to be re-encrypted."""
    mk = unlock(path, old)
    kdf = dict(_load(path)["kdf"])
    kdf["salt"] = _b64e(crypto.random_bytes(16))       # fresh salt
    try:
        _write(path, kdf, mk, new)
    finally:
        crypto.wipe(mk)
