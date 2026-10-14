# securefm

A secure command-line file manager that encrypts and decrypts files on the
local machine. Secure Programming course project.

Files are encrypted with **AES-256-GCM** using a random key per file. Each file
key is wrapped with a master key, which is stored in a keystore that is itself
encrypted with a key derived from the user's master password using **Argon2id**.

## Scope

**In scope**

- Creating a password-protected keystore (`init`)
- Encrypting and decrypting single files of any size (streaming, 64 KiB chunks)
- Detecting any modification, truncation or reordering of encrypted files
- Checking integrity without writing plaintext to disk (`verify`)
- Changing the master password without re-encrypting files (`passwd`)
- Safe file handling: no symlink following, no silent overwrites, atomic
  writes, no partial plaintext left behind on failure, private (0600) outputs

**Out of scope**

- Encrypting whole directories (planned: later checkpoint)
- Secure deletion of the original file (not reliable on SSDs / journaling
  filesystems, so the tool does not pretend to do it)
- Sharing files between different users / keystores
- Protection against an attacker who controls the machine while the tool runs
  (keylogger, root access)

## Planned commands

| Command | Description | Password |
|---|---|---|
| `sfm init` | Create a new keystore, asks for a new master password twice | new |
| `sfm encrypt FILE [-o OUT] [--force]` | Encrypt `FILE` to `FILE.sfm` (original is kept) | yes |
| `sfm decrypt FILE.sfm [-o OUT] [--force]` | Decrypt to `FILE` (or `OUT`) | yes |
| `sfm verify FILE.sfm` | Authenticate every chunk, write nothing | yes |
| `sfm info FILE.sfm` | Show header metadata (version, file id, chunk size) | no |
| `sfm passwd` | Change the master password | yes |
| `sfm --keystore PATH ...` | Use a keystore other than the default | – |

Exit codes: `0` success, `1` error, `2` usage error, `130` aborted (Ctrl+C).
The master password is **only** read from the terminal with no echo; it is
never accepted as an argument or environment variable.

Default keystore location: `~/.config/sfm/keystore.json` (override with
`SFM_HOME` or `--keystore`). **Back it up** – without it no file can be
decrypted.

## Build and run

Requirements: Python 3.11+ on Linux or macOS (Windows works, but without the
symlink and core-dump protections).

```bash
git clone <this-repo> && cd securefm
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

sfm init
echo "hello" > note.txt
sfm encrypt note.txt          # -> note.txt.sfm
sfm info note.txt.sfm
sfm decrypt note.txt.sfm -o note-copy.txt
```

Without installing: `python -m sfm --help`.

### Tests

```bash
pytest -q          # round-trip, tampering, truncation, symlinks, overwrite, permissions, passwd
pip-audit          # known-vulnerable dependencies
```

## Project layout

```
sfm/cli.py         argument parsing, password prompts, error handling
sfm/keystore.py    master-key wrapping with Argon2id + AES-256-GCM
sfm/fileformat.py  .sfm file format, streaming chunked AES-256-GCM
sfm/fileio.py      safe file handling (O_NOFOLLOW, temp files, atomic publish, ownership checks)
sfm/crypto.py      the only module that calls crypto libraries (SecureBuffer, mlock)
sfm/audit.py       structured JSON audit logging
tests/             pytest suite (37 tests)
docs/              architecture diagram
```

## Known limitations

Python cannot guarantee that secrets are erased from memory (immutable `bytes`,
garbage collector, copies inside libraries). The tool keeps keys in
`bytearray`s, wipes them after use, keeps them in memory only for one command
and disables core dumps, but this is best effort.

## Status

- [x] Checkpoint 1: design, threat model, repository, working core with tests
- [x] Checkpoint 2: core requirements implemented — CLI, encryption, auth, input validation
- [x] Checkpoint 3: near-final — secure memory, logging, access control, full tests, draft report
- [ ] Next: final polish, security testing

## Progress notes

### Checkpoint 2 (core requirements implemented)

All planned commands are working: `init`, `encrypt`, `decrypt`, `verify`,
`info`, `passwd`. The CLI parses arguments with `argparse`, validates file
paths and command arguments before touching keys or files, and reads the
master password from the terminal with no echo.

**Encryption / decryption.** Files are encrypted with AES-256-GCM using a
random per-file key (DEK). The DEK is wrapped with the master key, which is
stored in a keystore encrypted with Argon2id. Streaming chunked encryption
handles files of any size and detects modification, truncation, reordering
and appended data.

**Authentication.** The master password is verified by attempting to unwrap
the master key with Argon2id + AES-256-GCM. No password hash is stored
separately — a wrong password produces an `InvalidTag` error. KDF
parameters are checked against OWASP minimums so an attacker cannot
downgrade them by editing the keystore.

**Input validation.** Paths are checked for null bytes, emptiness and
length limits. Missing files are caught before the password prompt.
Double-encryption (encrypting a `.sfm` file) and self-overwrite (output
equals input) are rejected. Output directory existence is verified up front.
Symlink inputs and outputs are blocked. Existing files are never overwritten
without `--force`.

**Tests.** 24 pytest tests cover round-trip encryption at multiple sizes,
wrong-password rejection, four tampering scenarios, KDF downgrade
protection, overwrite safety, symlink blocking, permissions, password
changes and all new validation checks.
