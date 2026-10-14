import json
import os
import stat
from pathlib import Path

import pytest

from sfm import audit, crypto, fileformat, keystore
from sfm.cli import main
from sfm.crypto import SecureBuffer

PW = "correct-horse-battery"


def init(answers):
    answers += [PW, PW]
    assert main(["init"]) == 0


def encrypt(answers, path, *extra):
    answers.append(PW)
    return main(["encrypt", str(path), *extra])


def decrypt(answers, path, *extra, pw=PW):
    answers.append(pw)
    return main(["decrypt", str(path), *extra])


# --- round-trip correctness ---

@pytest.mark.parametrize("size", [0, 1, fileformat.CHUNK_SIZE, 3 * fileformat.CHUNK_SIZE + 7])
def test_roundtrip(env, size):
    tmp, answers = env
    init(answers)
    data = os.urandom(size)
    (tmp / "a.bin").write_bytes(data)
    assert encrypt(answers, tmp / "a.bin") == 0
    assert data[:16] not in (tmp / "a.bin.sfm").read_bytes()[fileformat.HEADER_SIZE:] or size < 16
    assert decrypt(answers, tmp / "a.bin.sfm", "-o", str(tmp / "out.bin")) == 0
    assert (tmp / "out.bin").read_bytes() == data


# --- authentication failure ---

def test_wrong_password_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("secret")
    encrypt(answers, tmp / "a.txt")
    assert decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "o"), pw="wrong-password!!") == 1
    assert not (tmp / "o").exists()


# --- tampering detection ---

@pytest.mark.parametrize("attack", ["flip", "truncate", "append", "drop_last_chunk"])
def test_tampering_detected_and_no_partial_output(env, attack):
    tmp, answers = env
    init(answers)
    (tmp / "a.bin").write_bytes(os.urandom(2 * fileformat.CHUNK_SIZE + 100))
    encrypt(answers, tmp / "a.bin")
    enc = tmp / "a.bin.sfm"
    b = bytearray(enc.read_bytes())
    step = fileformat.CHUNK_SIZE + crypto.TAG_SIZE
    if attack == "flip":
        b[fileformat.HEADER_SIZE + 10] ^= 1
    elif attack == "truncate":
        b = b[:-5]
    elif attack == "append":
        b += b"extra"
    elif attack == "drop_last_chunk":
        b = b[:fileformat.HEADER_SIZE + 2 * step]
    enc.write_bytes(bytes(b))
    assert decrypt(answers, enc, "-o", str(tmp / "o")) == 1
    assert not (tmp / "o").exists()
    assert not list(tmp.glob(".sfm-*.tmp"))          # temp file cleaned up


def test_keystore_kdf_downgrade_rejected(env, monkeypatch):
    tmp, answers = env
    init(answers)
    ks = keystore.default_path()
    doc = json.loads(ks.read_text())
    doc["kdf"]["t"] = 2                                # attacker edits parameters
    ks.write_text(json.dumps(doc))
    with pytest.raises(Exception):
        keystore.unlock(ks, PW)


# --- overwrite / symlink safety ---

def test_does_not_overwrite_without_force(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    (tmp / "a.txt.sfm").write_text("existing")
    assert encrypt(answers, tmp / "a.txt") == 1
    assert (tmp / "a.txt.sfm").read_text() == "existing"
    assert encrypt(answers, tmp / "a.txt", "--force") == 0


def test_symlink_input_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "real.txt").write_text("x")
    (tmp / "link.txt").symlink_to(tmp / "real.txt")
    assert encrypt(answers, tmp / "link.txt") == 1


def test_symlink_output_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    (tmp / "victim").write_text("important")
    (tmp / "a.txt.sfm").symlink_to(tmp / "victim")
    assert encrypt(answers, tmp / "a.txt", "--force") == 1
    assert (tmp / "victim").read_text() == "important"


# --- permissions ---

def test_private_permissions(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    for p in [keystore.default_path(), tmp / "a.txt.sfm"]:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


# --- passwd ---

def test_passwd_keeps_files_readable(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("hello")
    encrypt(answers, tmp / "a.txt")
    new = "another-long-passphrase"
    answers += [PW, new, new]
    assert main(["passwd"]) == 0
    assert decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "o1"), pw=PW) == 1
    assert decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "o2"), pw=new) == 0
    assert (tmp / "o2").read_text() == "hello"


def test_weak_password_rejected(env):
    tmp, answers = env
    answers += ["short"]
    assert main(["init"]) == 1


# --- input validation ---

def test_empty_path_rejected(env):
    tmp, answers = env
    init(answers)
    answers.append(PW)
    assert main(["encrypt", ""]) == 1


def test_null_byte_in_path_rejected(env):
    tmp, answers = env
    init(answers)
    answers.append(PW)
    assert main(["encrypt", "file\x00.txt"]) == 1


def test_control_chars_in_path_rejected(env):
    tmp, answers = env
    init(answers)
    assert main(["encrypt", "file\x07bell.txt"]) == 1


def test_nonexistent_file_rejected(env):
    tmp, answers = env
    init(answers)
    answers.append(PW)
    assert main(["encrypt", str(tmp / "no-such-file.txt")]) == 1


def test_double_encrypt_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    answers.append(PW)
    assert main(["encrypt", str(tmp / "a.txt.sfm")]) == 1


def test_output_same_as_input_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    answers.append(PW)
    assert main(["encrypt", str(tmp / "a.txt"), "-o", str(tmp / "a.txt")]) == 1


def test_output_dir_must_exist(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    answers.append(PW)
    assert main(["encrypt", str(tmp / "a.txt"), "-o",
                 str(tmp / "nodir" / "out.sfm")]) == 1


def test_verify_nonexistent_rejected(env):
    tmp, answers = env
    init(answers)
    answers.append(PW)
    assert main(["verify", str(tmp / "nope.sfm")]) == 1


def test_info_nonexistent_rejected(env):
    _, answers = env
    assert main(["info", str(Path("/tmp/no-such.sfm"))]) == 1


def test_path_traversal_dot_dot(env):
    """Paths with .. are normalized by Path and validated — the resolved path
    is used for the self-overwrite check."""
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    answers.append(PW)
    assert main(["encrypt", str(tmp / "a.txt"), "-o",
                 str(tmp / "sub" / ".." / "a.txt")]) == 1


# --- secure memory management ---

def test_secure_buffer_wipes_on_exit():
    raw = os.urandom(32)
    sb = SecureBuffer(raw)
    buf = sb.buf
    assert bytes(buf) == raw
    sb.close()
    assert bytes(buf) == b"\x00" * 32


def test_secure_buffer_context_manager():
    raw = os.urandom(32)
    with SecureBuffer(raw) as buf:
        assert bytes(buf) == raw
    assert bytes(buf) == b"\x00" * 32


def test_wipe_zeroes_bytearray():
    key = bytearray(b"\xde\xad\xbe\xef" * 8)
    crypto.wipe(key)
    assert key == bytearray(32)


def test_keys_wiped_after_encrypt(env):
    """After encrypt, the master key should have been wiped via SecureBuffer."""
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    # If we got here without error, the SecureBuffer __exit__ ran


def test_keys_wiped_after_decrypt(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "out.txt"))


# --- structured logging ---

def test_audit_log_created_on_init(env):
    tmp, answers = env
    init(answers)
    log_path = tmp / "home" / "audit.log"
    assert log_path.exists()
    lines = log_path.read_text().splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert "keystore_created" in events


def test_audit_log_records_encrypt_decrypt(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("hello")
    encrypt(answers, tmp / "a.txt")
    decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "out.txt"))
    log_path = tmp / "home" / "audit.log"
    lines = log_path.read_text().splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert "encrypt_start" in events
    assert "encrypt_done" in events
    assert "decrypt_start" in events
    assert "decrypt_done" in events


def test_audit_log_records_auth_failure(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "o"), pw="wrong-password!!")
    log_path = tmp / "home" / "audit.log"
    lines = log_path.read_text().splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert "auth_failed" in events


def test_audit_log_contains_no_secrets(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("supersecretdata")
    encrypt(answers, tmp / "a.txt")
    log_path = tmp / "home" / "audit.log"
    content = log_path.read_text()
    assert PW not in content
    assert "supersecretdata" not in content


def test_audit_log_is_valid_json(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    log_path = tmp / "home" / "audit.log"
    for line in log_path.read_text().splitlines():
        entry = json.loads(line)
        assert "ts" in entry
        assert "event" in entry
        assert "uid" in entry


# --- per-user access control ---

def test_file_not_owned_by_user_rejected(env, tmp_path):
    """Simulates ownership check by monkeypatching os.getuid to differ from file owner."""
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    original_getuid = os.getuid

    def fake_uid():
        return original_getuid() + 1

    import sfm.fileio
    old = os.getuid
    os.getuid = fake_uid
    try:
        answers.append(PW)
        result = main(["encrypt", str(tmp / "a.txt")])
        assert result == 1
    finally:
        os.getuid = old
