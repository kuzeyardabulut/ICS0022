class SFMError(Exception):
    """Expected, user-facing error. The message is safe to print."""


class AuthError(SFMError):
    """Wrong master password or tampered keystore (deliberately not distinguished)."""


class IntegrityError(SFMError):
    """Encrypted file is corrupted, truncated or was modified."""
