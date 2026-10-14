import json
import os
import stat
from pathlib import Path

import pytest

from sfm import crypto, fileformat, keystore
from sfm.cli import main

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


def test_wrong_password_rejected(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("secret")
    encrypt(answers, tmp / "a.txt")
    assert decrypt(answers, tmp / "a.txt.sfm", "-o", str(tmp / "o"), pw="wrong-password!!") == 1
    assert not (tmp / "o").exists()


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


def test_private_permissions(env):
    tmp, answers = env
    init(answers)
    (tmp / "a.txt").write_text("x")
    encrypt(answers, tmp / "a.txt")
    for p in [keystore.default_path(), tmp / "a.txt.sfm"]:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


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
