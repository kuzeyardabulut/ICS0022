"""
Structured audit logging.

Every security-relevant event is logged as a JSON object so logs can be parsed
by monitoring tools. Secrets (passwords, keys, plaintext) are NEVER included
in any log record — only event type, file paths, sizes and outcomes.

Log destination: ``~/.config/sfm/audit.log`` (or ``$SFM_HOME/audit.log``).
"""
import json
import logging
import os
import time
from pathlib import Path


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(record.created)),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
            "uid": os.getuid(),
        }
        for key in ("file", "output", "bytes", "reason", "command"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        return json.dumps(entry)


def _log_path() -> Path:
    home = os.environ.get("SFM_HOME")
    base = Path(home) if home else Path.home() / ".config" / "sfm"
    return base / "audit.log"


_logger: logging.Logger | None = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    _logger = logging.getLogger("sfm.audit")
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    path = _log_path()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        old_mask = os.umask(0o077)
        try:
            fh.stream.close()
            fh.stream = open(path, "a", encoding="utf-8")
        finally:
            os.umask(old_mask)
        fh.setFormatter(_JSONFormatter())
        _logger.addHandler(fh)
    except OSError:
        _logger.addHandler(logging.NullHandler())
    return _logger


def log_event(event: str, *, level: int = logging.INFO, **kwargs) -> None:
    logger = get_logger()
    record = logger.makeRecord(
        "sfm.audit", level, "", 0, event, (), None,
    )
    record.event = event
    for k, v in kwargs.items():
        setattr(record, k, v)
    logger.handle(record)


def reset():
    global _logger
    if _logger is not None:
        for h in _logger.handlers[:]:
            _logger.removeHandler(h)
            h.close()
        _logger = None
