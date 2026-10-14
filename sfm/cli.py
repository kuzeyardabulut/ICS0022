"""
Command-line interface.

  sfm init                         create the keystore (asks for a new master password)
  sfm encrypt FILE [-o OUT] [--force]
  sfm decrypt FILE.sfm [-o OUT] [--force]
  sfm verify FILE.sfm              check integrity without writing plaintext
  sfm info FILE.sfm                show header metadata (no password needed)
  sfm passwd                       change the master password

Passwords are only ever read with getpass (no echo) - never from arguments or
environment variables, so they don't end up in shell history or `ps` output.
"""
import argparse
import getpass
import io
import logging
import os
import sys
from pathlib import Path

from . import __version__, audit, fileformat, keystore
from .crypto import SecureBuffer, wipe
from .errors import SFMError
from .fileio import open_input, safe_output

MIN_PASSWORD_LEN = 12
COMMON = {"password1234", "123456789012", "qwertyuiop12", "passwordpassword"}
MAX_PATH_LEN = 4096
_CONTROL_CHARS = set(range(0, 32)) - {ord("\t")}


def _harden_process():
    """Disable core dumps so keys can't end up in a crash dump (POSIX only)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def _validate_path(raw: str, *, must_exist: bool = False, check_parent: bool = False) -> Path:
    if not raw or not raw.strip():
        raise SFMError("file path must not be empty")
    if "\x00" in raw:
        raise SFMError("file path contains null bytes")
    if any(ord(c) in _CONTROL_CHARS for c in raw):
        raise SFMError("file path contains control characters")
    if len(raw) > MAX_PATH_LEN:
        raise SFMError(f"file path exceeds {MAX_PATH_LEN} characters")

    path = Path(raw)
    resolved = path.resolve()

    if must_exist and not path.exists():
        raise SFMError(f"{path}: file not found")
    if check_parent:
        parent = path.parent if str(path.parent) != "." else Path(".")
        if not parent.exists():
            raise SFMError(f"{parent}: output directory does not exist")
    return path


def _resolve_output(src_path: Path, output_arg: str | None, suffix: str) -> Path:
    if output_arg:
        out = _validate_path(output_arg, check_parent=True)
    elif suffix and src_path.suffix == suffix:
        out = src_path.with_suffix("")
    elif suffix:
        raise SFMError("cannot guess output name, use -o OUT")
    else:
        out = src_path.with_name(src_path.name + ".sfm")
        _validate_path(str(out), check_parent=True)
    if out.resolve() == src_path.resolve():
        raise SFMError("output path must differ from input path")
    return out


def _ask_password(prompt="Master password: ") -> str:
    return getpass.getpass(prompt)


def _ask_new_password() -> str:
    pw = getpass.getpass("New master password: ")
    if len(pw) < MIN_PASSWORD_LEN:
        raise SFMError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if pw.lower() in COMMON or len(set(pw)) < 5:
        raise SFMError("password is too weak")
    if getpass.getpass("Repeat new master password: ") != pw:
        raise SFMError("passwords do not match")
    return pw


def _keystore_path(args) -> Path:
    return Path(args.keystore) if args.keystore else keystore.default_path()


def cmd_init(args):
    path = _keystore_path(args)
    if path.exists():
        raise SFMError(f"keystore already exists at {path}")
    keystore.create(path, _ask_new_password())
    audit.log_event("keystore_created", command="init")
    print(f"Keystore created at {path}")
    print("Back it up: without it (and the password) your files cannot be decrypted.")


def cmd_encrypt(args):
    src_path = _validate_path(args.file, must_exist=True)
    if src_path.suffix == ".sfm":
        raise SFMError(f"{src_path}: file is already encrypted (has .sfm extension)")
    out = _resolve_output(src_path, args.output, "")
    audit.log_event("encrypt_start", command="encrypt", file=str(src_path), output=str(out))
    with SecureBuffer(keystore.unlock(_keystore_path(args), _ask_password())) as mk:
        with open_input(src_path) as src, safe_output(out, args.force) as dst:
            info = fileformat.encrypt_stream(mk, src, dst)
    audit.log_event("encrypt_done", command="encrypt", file=str(src_path), bytes=info["plaintext_bytes"])
    print(f"Encrypted {info['plaintext_bytes']} bytes -> {out}")
    print("Note: the original file was NOT deleted.")


def cmd_decrypt(args):
    src_path = _validate_path(args.file, must_exist=True)
    out = _resolve_output(src_path, args.output, ".sfm")
    audit.log_event("decrypt_start", command="decrypt", file=str(src_path), output=str(out))
    with SecureBuffer(keystore.unlock(_keystore_path(args), _ask_password())) as mk:
        with open_input(src_path) as src, safe_output(out, args.force) as dst:
            n = fileformat.decrypt_stream(mk, src, dst)
    audit.log_event("decrypt_done", command="decrypt", file=str(src_path), bytes=n)
    print(f"Decrypted {n} bytes -> {out}")


def cmd_verify(args):
    src_path = _validate_path(args.file, must_exist=True)
    audit.log_event("verify_start", command="verify", file=str(src_path))
    with SecureBuffer(keystore.unlock(_keystore_path(args), _ask_password())) as mk:
        with open_input(src_path) as src:
            n = fileformat.decrypt_stream(mk, src, _NullWriter())
    audit.log_event("verify_done", command="verify", file=str(src_path), bytes=n)
    print(f"OK: {args.file} is intact ({n} bytes of plaintext)")


def cmd_info(args):
    src_path = _validate_path(args.file, must_exist=True)
    with open_input(src_path) as src:
        h = fileformat.read_header(src)
    print(f"format version : {h['version']}")
    print(f"file id        : {h['file_id'].hex()}")
    print(f"chunk size     : {h['chunk_size']} bytes")
    print("cipher         : AES-256-GCM, per-file key wrapped with master key")


def cmd_passwd(args):
    path = _keystore_path(args)
    old = _ask_password("Current master password: ")
    keystore.change_password(path, old, _ask_new_password())
    audit.log_event("passwd_changed", command="passwd")
    print("Master password changed. Existing encrypted files still work.")


class _NullWriter(io.RawIOBase):
    def writable(self):
        return True

    def write(self, b):
        return len(b)


def build_parser():
    p = argparse.ArgumentParser(prog="sfm", description="Secure file manager: encrypt and decrypt files.")
    p.add_argument("--version", action="version", version=f"sfm {__version__}")
    p.add_argument("--keystore", help="path to keystore.json (default: ~/.config/sfm/keystore.json)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new keystore").set_defaults(func=cmd_init)

    for name, func, helptext in [("encrypt", cmd_encrypt, "encrypt a file"),
                                 ("decrypt", cmd_decrypt, "decrypt an .sfm file")]:
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("file")
        sp.add_argument("-o", "--output", help="output path")
        sp.add_argument("--force", action="store_true", help="overwrite existing output")
        sp.set_defaults(func=func)

    sp = sub.add_parser("verify", help="check an .sfm file without decrypting to disk")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("info", help="show metadata of an .sfm file")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_info)

    sub.add_parser("passwd", help="change the master password").set_defaults(func=cmd_passwd)
    return p


def main(argv=None) -> int:
    _harden_process()
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except SFMError as e:
        audit.log_event("command_failed", level=logging.WARNING,
                        command=args.command, reason=str(e))
        print(f"sfm: error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nsfm: aborted", file=sys.stderr)
        return 130
    except Exception:
        audit.log_event("internal_error", level=logging.ERROR, command=args.command)
        print("sfm: error: unexpected internal error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
