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
