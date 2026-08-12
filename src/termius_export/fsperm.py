"""Platform-dependent filesystem writes and permission hardening.

POSIX behaviour is exactly what ``cli.py`` performed inline before this module existed:
``chmod 0700`` on directories, ``chmod <mode>`` on files, and a plain ``write_text``.

Windows needs three different things, two of which fail silently:

1. ``os.chmod`` can only toggle the read-only attribute there - every other bit is ignored -
   so ``0600`` on a private key protects nothing and the key simply inherits the parent
   directory's ACL. The fix is an explicit ACL via ``icacls``, which is also what Microsoft's
   own OpenSSH documentation prescribes for private key permissions.
2. ``Path.write_text`` defaults to ``newline=None``, translating every ``\\n`` to
   ``os.linesep``. On Windows that yields CRLF private keys and, because ``csv.writer``
   already emits ``\\r\\n``, a ``hosts.csv`` full of ``\\r\\r\\n``.
3. Well-known ACL principal names are localized on non-English Windows, so the principal must
   be a SID.

Both (1) and (2) are invisible on Linux, where ``chmod`` works and ``os.linesep`` is already
``\\n``. No amount of testing on the development platform surfaces them.

Two decisions worth keeping:

- **The ACL goes on the directory, not on each file.** ``(OI)(CI)`` makes new files inherit
  it, so one ``icacls`` call covers a whole key directory instead of one process spawn per
  exported key.
- **Failures are reported, never swallowed.** See ``warnings()``.
"""

from __future__ import annotations

import csv
import io
import os
import pathlib
import shutil
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"

_secured: set[pathlib.Path] = set()
_warnings: list[str] = []


def warnings() -> list[str]:
    """Hardening problems encountered so far, for the run summary."""
    return list(_warnings)


def _warn(message: str) -> None:
    _warnings.append(message)
    print(f"warning: {message}", file=sys.stderr)


def _parse_sid(whoami_output: str) -> str | None:
    """Extract the SID from ``whoami /user /fo csv /nh`` output.

    The line looks like ``"desktop-abc\\alice","S-1-5-21-..."``. Parsed with the csv module
    because the user name may contain a space.
    """
    row = next(csv.reader(io.StringIO(whoami_output.strip())), None)
    if not row or len(row) < 2:
        return None
    sid = row[1].strip()
    return sid if sid.startswith("S-1-") else None


def _icacls_args(path: str | pathlib.Path, sid: str) -> list[str]:
    """Build the icacls argv.

    ``/inheritance:r`` drops inherited ACEs, ``/grant:r`` replaces rather than adds, and
    ``(OI)(CI)F`` gives the user full control that new files and subdirectories inherit.
    """
    return ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"]


def _current_user_sid() -> str | None:
    if not shutil.which("whoami"):
        return None
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            # Unlike verify.py's helpers, whoami and icacls are Windows console programs:
            # they emit the console/ANSI codepage, not UTF-8, so the locale default is the
            # right codec here. errors="replace" only stops a non-ASCII user name from
            # raising - the SID field this parses is pure ASCII either way.
            errors="replace",
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    return _parse_sid(result.stdout)


def _harden_dir(path: pathlib.Path) -> None:
    """Apply the platform's directory protection. Split out so tests can substitute it."""
    if not IS_WINDOWS:
        os.chmod(path, 0o700)
        return

    if not shutil.which("icacls"):
        _warn(f"icacls not found; {path} keeps inherited permissions and may be readable by other accounts")
        return

    sid = _current_user_sid()
    if sid is None:
        _warn(f"could not determine the current user's SID; {path} keeps inherited permissions")
        return

    try:
        result = subprocess.run(
            _icacls_args(path, sid),
            capture_output=True,
            text=True,
            # icacls messages are localized and in the console codepage; see _current_user_sid.
            errors="replace",
            timeout=60,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        _warn(f"icacls failed on {path} ({exc}); it keeps inherited permissions")
        return

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        _warn(f"icacls failed on {path}: {detail[0] if detail else 'unknown error'}")


def secure_dir(path: str | pathlib.Path) -> None:
    """Restrict a directory to the current user. Idempotent per path.

    Memoized because every private write hardens its parent directory. On POSIX that only
    saves a redundant syscall and the end state is identical; on Windows it avoids spawning
    one ``icacls`` process per exported key.
    """
    p = pathlib.Path(path)
    if p in _secured:
        return
    _secured.add(p)
    _harden_dir(p)


def secure_file(path: str | pathlib.Path, mode: int) -> None:
    """Restrict a single file.

    Deliberately a no-op on Windows: the file already inherits the restrictive ACL that
    ``secure_dir`` put on its parent, so a per-file ``icacls`` call would be redundant. This
    does mean public keys and known_hosts (mode 0644) end up user-only on Windows, which is
    harmless - they hold no secrets and nothing reads them from another account.
    """
    if IS_WINDOWS:
        return
    pathlib.Path(path).chmod(mode)


def write_private(path: str | pathlib.Path, content: str, mode: int = 0o600) -> None:
    """Write a file that may contain secrets, with its directory hardened first.

    ``newline="\\n"`` disables translation. Without it ``write_text`` turns every ``\\n`` into
    ``os.linesep``, which on Windows means CRLF private keys - OpenSSH rejects those - and a
    ``hosts.csv`` of ``\\r\\r\\n``, since ``csv.writer`` already emits ``\\r\\n``. On POSIX
    ``os.linesep`` is already ``\\n``, so this is a byte-level no-op there.

    The parent is hardened *before* the file is written so that on Windows the new file
    inherits the restrictive ACL rather than being created under the old one.
    """
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    secure_dir(p.parent)
    p.write_text(content, encoding="utf-8", newline="\n")
    secure_file(p, mode)
