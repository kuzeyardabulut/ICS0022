"""
Encrypted file format (.sfm), streaming AES-256-GCM.

  Header (93 bytes), authenticated with every chunk:
    magic      4   b"SFM\\x01"
    version    1
    chunk_size 4   big-endian, plaintext bytes per chunk
    file_id   16   random
    dek_nonce 12
    wrapped   48   AES-256-GCM(MK, DEK) = 32-byte DEK + 16-byte tag
    prefix     8   random nonce prefix for the chunks

  Body: chunks of chunk_size plaintext bytes, each sealed with
    nonce = prefix || counter(4, big-endian)
    aad   = header || counter || last_flag(1)
  The last chunk has last_flag = 1 (it may be empty). This detects modified,
  reordered, dropped and truncated chunks, and appended data.
"""
import struct

from . import crypto
from .errors import IntegrityError, SFMError

MAGIC = b"SFM\x01"
VERSION = 1
CHUNK_SIZE = 64 * 1024
_HDR = struct.Struct(">4sBI16s12s48s8s")
HEADER_SIZE = _HDR.size
MAX_CHUNKS = 2 ** 32


def _dek_aad(magic, version, chunk_size, file_id) -> bytes:
    return b"sfm-dek" + magic + bytes([version]) + struct.pack(">I", chunk_size) + file_id


def _chunk(key, prefix, header, counter, last, data, encrypt):
    if counter >= MAX_CHUNKS:
        raise SFMError("file too large")
    nonce = prefix + struct.pack(">I", counter)
    aad = header + struct.pack(">I", counter) + bytes([1 if last else 0])
    return (crypto.seal if encrypt else crypto.open_)(key, nonce, data, aad)


def encrypt_stream(mk, src, dst) -> dict:
    file_id = crypto.random_bytes(16)
    dek = bytearray(crypto.random_bytes(crypto.KEY_SIZE))
    dek_nonce = crypto.random_bytes(crypto.NONCE_SIZE)
    wrapped = crypto.seal(mk, dek_nonce, bytes(dek),
                          _dek_aad(MAGIC, VERSION, CHUNK_SIZE, file_id))
    prefix = crypto.random_bytes(8)
    header = _HDR.pack(MAGIC, VERSION, CHUNK_SIZE, file_id, dek_nonce, wrapped, prefix)
    dst.write(header)
    try:
        counter, total = 0, 0
        block = src.read(CHUNK_SIZE)
        while True:
            nxt = src.read(CHUNK_SIZE)
            last = not nxt
            dst.write(_chunk(dek, prefix, header, counter, last, block, True))
            total += len(block)
            if last:
                break
            block, counter = nxt, counter + 1
    finally:
        crypto.wipe(dek)
    return {"file_id": file_id.hex(), "plaintext_bytes": total}


def read_header(src) -> dict:
    header = src.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE:
        raise IntegrityError("not an sfm file (too short)")
    magic, version, chunk_size, file_id, dek_nonce, wrapped, prefix = _HDR.unpack(header)
    if magic != MAGIC:
        raise IntegrityError("not an sfm file")
    if version != VERSION:
        raise SFMError(f"unsupported file format version {version}")
    if not 1024 <= chunk_size <= 16 * 1024 * 1024:
        raise IntegrityError("invalid header")
    return {"raw": header, "version": version, "chunk_size": chunk_size, "file_id": file_id,
            "dek_nonce": dek_nonce, "wrapped": wrapped, "prefix": prefix}


def decrypt_stream(mk, src, dst) -> int:
    h = read_header(src)
    try:
        dek = bytearray(crypto.open_(mk, h["dek_nonce"], h["wrapped"],
                                     _dek_aad(MAGIC, h["version"], h["chunk_size"], h["file_id"])))
    except crypto.InvalidTag:
        raise IntegrityError("file was encrypted with a different keystore, or header was modified") from None
    step = h["chunk_size"] + crypto.TAG_SIZE
    try:
        counter, total = 0, 0
        block = src.read(step)
        while True:
            nxt = src.read(step)
            last = not nxt
            try:
                pt = _chunk(dek, h["prefix"], h["raw"], counter, last, block, False)
            except crypto.InvalidTag:
                raise IntegrityError("file is corrupted, truncated or was modified") from None
            dst.write(pt)
            total += len(pt)
            if last:
                return total
            block, counter = nxt, counter + 1
    finally:
        crypto.wipe(dek)
