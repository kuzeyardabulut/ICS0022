import pytest

from sfm import audit, crypto


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Cheap Argon2 parameters so the test suite runs quickly."""
    monkeypatch.setattr(crypto, "DEFAULT_KDF", {"t": 1, "m": 8, "p": 1})
    monkeypatch.setattr(crypto, "MIN_KDF", {"t": 1, "m": 8, "p": 1})


@pytest.fixture(autouse=True)
def reset_audit():
    """Reset the audit logger so each test gets a fresh log file."""
    yield
    audit.reset()


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated keystore + scripted password prompts."""
    monkeypatch.setenv("SFM_HOME", str(tmp_path / "home"))
    answers = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": answers.pop(0))
    return tmp_path, answers
