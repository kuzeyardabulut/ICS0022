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
import sys
from pathlib import Path

from . import __version__, fileformat, keystore
from .crypto import wipe
from .errors import SFMError
from .fileio import open_input, safe_output

MIN_PASSWORD_LEN = 12
COMMON = {"password1234", "123456789012", "qwertyuiop12", "passwordpassword"}


def _harden_process():
    """Disable core dumps so keys can't end up in a crash dump (POSIX only)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


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
    print(f"Keystore created at {path}")
    print("Back it up: without it (and the password) your files cannot be decrypted.")


def cmd_encrypt(args):
    src_path = Path(args.file)
    out = Path(args.output) if args.output else src_path.with_name(src_path.name + ".sfm")
    mk = keystore.unlock(_keystore_path(args), _ask_password())
    try:
        with open_input(src_path) as src, safe_output(out, args.force) as dst:
            info = fileformat.encrypt_stream(mk, src, dst)
    finally:
        wipe(mk)
    print(f"Encrypted {info['plaintext_bytes']} bytes -> {out}")
    print("Note: the original file was NOT deleted.")


def cmd_decrypt(args):
    src_path = Path(args.file)
    if args.output:
        out = Path(args.output)
    elif src_path.suffix == ".sfm":
        out = src_path.with_suffix("")
    else:
        raise SFMError("cannot guess output name, use -o OUT")
    mk = keystore.unlock(_keystore_path(args), _ask_password())
    try:
        # Plaintext goes to a private temp file and is published only if
        # every chunk authenticates; otherwise the temp file is removed.
        with open_input(src_path) as src, safe_output(out, args.force) as dst:
            n = fileformat.decrypt_stream(mk, src, dst)
    finally:
        wipe(mk)
    print(f"Decrypted {n} bytes -> {out}")


def cmd_verify(args):
    mk = keystore.unlock(_keystore_path(args), _ask_password())
    try:
        with open_input(Path(args.file)) as src:
            n = fileformat.decrypt_stream(mk, src, _NullWriter())
    finally:
        wipe(mk)
    print(f"OK: {args.file} is intact ({n} bytes of plaintext)")


def cmd_info(args):
    with open_input(Path(args.file)) as src:
        h = fileformat.read_header(src)
    print(f"format version : {h['version']}")
    print(f"file id        : {h['file_id'].hex()}")
    print(f"chunk size     : {h['chunk_size']} bytes")
    print("cipher         : AES-256-GCM, per-file key wrapped with master key")


def cmd_passwd(args):
    path = _keystore_path(args)
    old = _ask_password("Current master password: ")
    keystore.change_password(path, old, _ask_new_password())
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
        print(f"sfm: error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nsfm: aborted", file=sys.stderr)
        return 130
    except Exception:
        # Never show a stack trace (it could contain paths or data).
        print("sfm: error: unexpected internal error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
