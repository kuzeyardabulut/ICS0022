"""
Safe file handling.

  * Inputs are opened with O_NOFOLLOW and must be regular files (no symlinks,
    devices or FIFOs) - checked on the open descriptor, not the path (no TOCTOU).
  * Outputs are written to a private temp file (mode 0600) in the target
    directory, fsync'ed, and only then published atomically.
  * Existing files are never overwritten unless --force is given.
  * Output is only published after the whole operation succeeded, so a failed
    or tampered decryption leaves no partial plaintext behind.
  * Ownership is checked on the open file descriptor (not the path) to prevent
    TOCTOU races — the running user must own the file.
"""
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .errors import SFMError

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _check_owner(fd: int, path: Path) -> None:
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        raise SFMError(f"{path}: access denied (you do not own this file)")


def open_input(path: Path, *, check_ownership: bool = True):
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except FileNotFoundError:
        raise SFMError(f"{path}: file not found") from None
    except OSError:
        raise SFMError(f"{path}: cannot open (symbolic links are not allowed)") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise SFMError(f"{path}: not a regular file")
    if check_ownership:
        try:
            _check_owner(fd, path)
        except SFMError:
            os.close(fd)
            raise
    return os.fdopen(fd, "rb")


@contextmanager
def safe_output(path: Path, overwrite: bool = False):
    """Yield a writable file; publish it to `path` only if the block succeeds."""
    path = Path(path)
    directory = path.parent if str(path.parent) else Path(".")
    if path.is_symlink():
        raise SFMError(f"{path}: refusing to write through a symbolic link")
    if path.exists() and not overwrite:
        raise SFMError(f"{path}: already exists (use --force to overwrite)")
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".sfm-", suffix=".tmp")  # mode 0600
    try:
        with os.fdopen(fd, "wb") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)          # atomic: fails if path appeared meanwhile
            except FileExistsError:
                raise SFMError(f"{path}: already exists (use --force to overwrite)") from None
            os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def atomic_write_bytes(path: Path, data: bytes, overwrite: bool = False) -> None:
    with safe_output(path, overwrite=overwrite) as f:
        f.write(data)
