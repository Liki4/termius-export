# Windows Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `termius-export` run correctly on Windows: read `localKey` from Credential Manager, harden exported private keys with real ACLs, and stop corrupting output files.

**Architecture:** All new behaviour is reachable only under `sys.platform == "win32"`. A new `fsperm.py` owns every platform-dependent filesystem concern — permissions *and* the private write path — so `cli.py` acquires no platform branches. `localkey.py` gains a `ctypes`/`advapi32` backend alongside the existing `secret-tool` and `security` backends; its `CANDIDATE_SERVICES` list is unchanged because the measured Windows service name (`Termius`) is already in it.

**Tech Stack:** Python 3.11+, stdlib only for all new code (`ctypes`, `subprocess`, `csv`, `base64`, `unittest`). No new dependencies.

**Hard invariant, enforced in every task:** POSIX behaviour must be byte-for-byte unchanged. Linux is the verified development platform and macOS is validated on a separate track; neither may regress.

**Reference spec:** `docs/superpowers/specs/2026-08-12-windows-support-design.md`

---

## Two findings that shaped this plan

**1. `_write_private` must move out of `cli.py`.** The newline fix lives in `_write_private`,
but `cli.py` imports `crypto.py`, which needs `pynacl` — not installed on the development
machine. A test importing `cli` cannot run. Moving the function to `fsperm.write_private` makes
it testable with stdlib alone and gives `fsperm` one coherent responsibility: *writing files to
disk safely on this platform*. `cli.py` keeps a thin module-level alias so the rest of the file
is untouched.

**2. The unquoted `IdentityFile` defect is worse than the spec recorded.** Measured with the
real parser:

```
$ ssh -G -F cfg demo         # IdentityFile /tmp/First Last/id_ed25519
cfg line 3: keyword identityfile extra arguments at end of line

$ ssh -G -F cfg demo         # IdentityFile "/tmp/First Last/id_ed25519"
identityfile /tmp/First Last/id_ed25519
```

`ssh` rejects the **entire configuration file**, not just the offending host. On a Windows
account whose name contains a space, every host in the export would be unusable. The quoted
form is accepted and resolves with the space preserved.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/termius_export/fsperm.py` | **New.** Platform-dependent filesystem writes and permission hardening |
| `src/termius_export/localkey.py` | Add Credential Manager backend + Windows not-found message |
| `src/termius_export/cli.py` | Delegate to `fsperm`; surface warnings in the summary |
| `src/termius_export/writers/openssh.py` | Quote `IdentityFile` when the path contains whitespace |
| `src/termius_export/source.py` | Add Windows path to the not-found message |
| `tests/test_openssh_quoting.py` | **New.** Quoting predicate, POSIX no-change guarantee, `ssh -G` roundtrip |
| `tests/test_fsperm.py` | **New.** SID parsing, icacls arguments, POSIX modes, memoization |
| `tests/test_newlines.py` | **New.** Verbatim newline writing |
| `tests/test_localkey.py` | **New.** Blob decoding, import safety, messages, live Windows read |
| `README.md`, `CLAUDE.md` | Correct the false "Windows branch exists" claim |

**Test runner:** stdlib `unittest`.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

No pytest, ruff or nix is installed on the development machine, and neither `pynacl` nor
`ccl_chromium_reader` is importable there. `localkey`, `model`, `fsperm` and all writers import
with stdlib alone, which is what makes the suite runnable — and runnable unmodified on the
Windows test machine.

**Never import `termius_export.cli`, `termius_export.crypto` or `termius_export.source` from a
test.** They pull `pynacl` / `ccl_chromium_reader` and will fail to import.

---

## Task 1: Quote IdentityFile paths containing whitespace

**Files:**
- Modify: `src/termius_export/writers/openssh.py`
- Test: `tests/test_openssh_quoting.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_openssh_quoting.py`:

```python
"""IdentityFile quoting.

The critical assertion is the negative one: paths without whitespace must come out
byte-identical, because openssh.py is shared code rather than a platform branch and Linux
output must not change.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.writers.openssh import _quote_path


class QuotePathTests(unittest.TestCase):
    def test_path_without_spaces_is_returned_unchanged(self):
        path = "/home/alice/out/keys/id_ed25519"
        self.assertEqual(_quote_path(path), path)

    def test_windows_path_without_spaces_is_returned_unchanged(self):
        path = r"C:\Users\Alice\out\keys\id_ed25519"
        self.assertEqual(_quote_path(path), path)

    def test_path_with_space_is_quoted(self):
        self.assertEqual(
            _quote_path(r"C:\Users\First Last\out\keys\id_ed25519"),
            r'"C:\Users\First Last\out\keys\id_ed25519"',
        )

    def test_path_with_tab_is_quoted(self):
        self.assertEqual(_quote_path("/tmp/a\tb/key"), '"/tmp/a\tb/key"')

    def test_empty_path_is_returned_unchanged(self):
        self.assertEqual(_quote_path(""), "")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_openssh_quoting -v`
Expected: FAIL — `ImportError: cannot import name '_quote_path'`

- [ ] **Step 3: Write minimal implementation**

In `src/termius_export/writers/openssh.py`, add after the `_proxy_command` function:

```python
def _quote_path(path: str) -> str:
    """Double-quote an ssh_config path argument, but only when it needs it.

    An unquoted path containing a space is not merely wrong for that host - ssh rejects the
    whole file: "keyword identityfile extra arguments at end of line". Every host in the
    export becomes unusable. Quoting fixes it; ssh resolves the quoted form with the space
    preserved.

    Quoting unconditionally would also be correct, but it would change the generated file for
    every existing Linux user for no benefit, so quote exactly the paths that need it.

    A path containing a literal double quote is not representable in ssh_config and is not
    handled: it is an illegal character in Windows paths and vanishingly rare on POSIX.
    """
    return f'"{path}"' if any(c.isspace() for c in path) else path
```

Then change the `IdentityFile` line (currently `openssh.py:48`) from:

```python
                lines.append(f"    IdentityFile {key_path}")
```

to:

```python
                lines.append(f"    IdentityFile {_quote_path(key_path)}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_openssh_quoting -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add tests/test_openssh_quoting.py src/termius_export/writers/openssh.py
git commit -m "Quote IdentityFile paths containing whitespace

An unquoted spaced path makes ssh reject the entire config file, not just
that host, so on a Windows account named 'First Last' every exported host
would be unusable. Quoting is conditional so Linux output stays identical."
```

---

## Task 2: Prove ssh itself accepts the quoted form

Holds the change to the same standard as the writer's `roundtrip` label: parsed by OpenSSH, not
just string-compared. `ssh` is present on the development machine even though the Termius
dependencies are not.

**Files:**
- Test: `tests/test_openssh_quoting.py` (append)

- [ ] **Step 1: Write the test**

Append to `tests/test_openssh_quoting.py`, before the `if __name__` block:

```python
import shutil
import subprocess
import tempfile
from pathlib import Path

from termius_export.model import Host, Key, Model
from termius_export.writers import WriteContext
from termius_export.writers.openssh import OpenSshWriter


def _ssh_G(config_path, alias):
    out = subprocess.run(
        ["ssh", "-G", "-F", str(config_path), alias],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    values = {}
    for line in out.splitlines():
        head, _, tail = line.partition(" ")
        values.setdefault(head, tail.strip())
    return values


@unittest.skipUnless(shutil.which("ssh"), "ssh not installed")
class SshAcceptsQuotedIdentityFileTests(unittest.TestCase):
    def _render(self, key_path):
        key = Key(id="k1", label="test", file_base="id_ed25519", private_key="x")
        model = Model(hosts=[Host(id="h1", alias="demo", label="demo",
                                  address="10.0.0.1", port=2222, username="alice", key=key)])
        ctx = WriteContext(include_secrets=True, key_paths={"k1": key_path})
        return OpenSshWriter().write(model, ctx)[0].content

    def _resolve(self, key_path):
        content = self._render(key_path)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "sshconfig"
            cfg.write_text(content, encoding="utf-8", newline="\n")
            return _ssh_G(cfg, "demo"), content

    def test_ssh_resolves_host_with_spaced_key_path(self):
        values, content = self._resolve("/tmp/First Last/id_ed25519")
        self.assertIn('IdentityFile "/tmp/First Last/id_ed25519"', content)
        self.assertEqual(values["hostname"], "10.0.0.1")
        self.assertEqual(values["port"], "2222")
        self.assertEqual(values["user"], "alice")

    def test_ssh_resolves_host_with_plain_key_path(self):
        values, content = self._resolve("/tmp/plain/id_ed25519")
        self.assertIn("IdentityFile /tmp/plain/id_ed25519", content)
        self.assertNotIn('"', content)
        self.assertEqual(values["hostname"], "10.0.0.1")
```

- [ ] **Step 2: Run the test**

Run: `PYTHONPATH=src python3 -m unittest tests.test_openssh_quoting -v`
Expected: PASS, 7 tests. `ssh` is at `/usr/bin/ssh`, so the two new tests must actually run,
not skip.

- [ ] **Step 3: Commit**

```bash
git add tests/test_openssh_quoting.py
git commit -m "Verify quoted IdentityFile is accepted by ssh -G itself"
```

---

## Task 3: fsperm — SID lookup and icacls argument construction

Pure functions first, so the Windows logic is testable from Linux.

**Files:**
- Create: `src/termius_export/fsperm.py`
- Test: `tests/test_fsperm.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_fsperm.py`:

```python
"""Filesystem hardening helpers.

Everything here is pure logic, so it runs on any platform. Whether icacls actually restricts a
real directory is covered by the manual Windows procedure, not here.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.fsperm import _icacls_args, _parse_sid


class ParseSidTests(unittest.TestCase):
    def test_parses_sid_from_whoami_csv(self):
        out = '"desktop-abc\\alice","S-1-5-21-1111111111-2222222222-3333333333-1001"\n'
        self.assertEqual(_parse_sid(out), "S-1-5-21-1111111111-2222222222-3333333333-1001")

    def test_parses_sid_when_username_contains_a_space(self):
        out = '"desktop-abc\\First Last","S-1-5-21-9-8-7-1001"\n'
        self.assertEqual(_parse_sid(out), "S-1-5-21-9-8-7-1001")

    def test_returns_none_for_empty_output(self):
        self.assertIsNone(_parse_sid(""))

    def test_returns_none_when_second_field_is_not_a_sid(self):
        self.assertIsNone(_parse_sid('"desktop-abc\\alice","not-a-sid"\n'))

    def test_returns_none_when_only_one_field(self):
        self.assertIsNone(_parse_sid('"desktop-abc\\alice"\n'))


class IcaclsArgsTests(unittest.TestCase):
    def test_builds_expected_argument_vector(self):
        self.assertEqual(
            _icacls_args(r"C:\out", "S-1-5-21-9-8-7-1001"),
            ["icacls", r"C:\out", "/inheritance:r", "/grant:r", "*S-1-5-21-9-8-7-1001:(OI)(CI)F"],
        )

    def test_principal_is_a_sid_not_a_localized_name(self):
        # The test machine runs a Chinese Windows, where well-known principal names are
        # localized. A SID is invariant.
        args = _icacls_args(r"C:\out", "S-1-5-21-9-8-7-1001")
        self.assertTrue(args[-1].startswith("*S-1-"))

    def test_path_is_a_separate_argv_entry(self):
        # Never interpolated into a shell string: the path routinely contains spaces.
        args = _icacls_args(r"C:\Users\First Last\out", "S-1-5-21-9-8-7-1001")
        self.assertIn(r"C:\Users\First Last\out", args)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_fsperm -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'termius_export.fsperm'`

- [ ] **Step 3: Write minimal implementation**

Create `src/termius_export/fsperm.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_fsperm -v`
Expected: PASS, 8 tests

- [ ] **Step 5: Commit**

```bash
git add tests/test_fsperm.py src/termius_export/fsperm.py
git commit -m "Add fsperm with SID parsing and icacls argument construction

The principal is a SID rather than a name because well-known principal names
are localized on non-English Windows, where an English literal fails."
```

---

## Task 4: fsperm — secure_dir and secure_file

**Files:**
- Modify: `src/termius_export/fsperm.py`
- Test: `tests/test_fsperm.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fsperm.py`, before the `if __name__` block:

```python
import stat
import tempfile
from pathlib import Path

from termius_export import fsperm


@unittest.skipIf(fsperm.IS_WINDOWS, "POSIX permission semantics")
class PosixSecureTests(unittest.TestCase):
    def setUp(self):
        fsperm._secured.clear()

    def test_secure_dir_sets_0700(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "out"
            d.mkdir()
            d.chmod(0o755)
            fsperm.secure_dir(d)
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)

    def test_secure_file_sets_requested_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "key"
            f.write_text("x")
            f.chmod(0o644)
            fsperm.secure_file(f, 0o600)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

    def test_secure_file_honours_a_non_private_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "key.pub"
            f.write_text("x")
            fsperm.secure_file(f, 0o644)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)


class MemoizationTests(unittest.TestCase):
    def test_secure_dir_only_hardens_once_per_path(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "out"
            d.mkdir()
            original = fsperm._harden_dir
            fsperm._harden_dir = lambda p: calls.append(p)
            fsperm._secured.clear()
            try:
                fsperm.secure_dir(d)
                fsperm.secure_dir(d)
                fsperm.secure_dir(d)
            finally:
                fsperm._harden_dir = original
                fsperm._secured.clear()
        self.assertEqual(len(calls), 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_fsperm -v`
Expected: FAIL — `AttributeError: module 'termius_export.fsperm' has no attribute 'secure_dir'`

- [ ] **Step 3: Write the implementation**

Append to `src/termius_export/fsperm.py`:

```python
def _current_user_sid() -> str | None:
    if not shutil.which("whoami"):
        return None
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_fsperm -v`
Expected: PASS, 12 tests

- [ ] **Step 5: Commit**

```bash
git add tests/test_fsperm.py src/termius_export/fsperm.py
git commit -m "Add secure_dir and secure_file to fsperm

The ACL goes on the directory with (OI)(CI) inheritance rather than on each
file, so one icacls call covers a key directory instead of one process spawn
per exported key. Failures warn rather than passing silently."
```

---

## Task 5: fsperm — write_private with verbatim newlines

Moves `_write_private` out of `cli.py`, which cannot be imported by tests, and fixes the
newline translation defect.

**Files:**
- Modify: `src/termius_export/fsperm.py`
- Test: `tests/test_newlines.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_newlines.py`:

```python
"""Output must reach disk verbatim.

pathlib.Path.write_text defaults to newline=None, which translates every "\\n" to os.linesep.
On Windows that is "\\r\\n", so private keys become CRLF PEM and hosts.csv - whose csv.writer
already emits "\\r\\n" - becomes "\\r\\r\\n".

These assert on bytes, so they are a real fix on Windows and a regression guard on POSIX.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "src")

from termius_export.fsperm import write_private

PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n"


class VerbatimNewlineTests(unittest.TestCase):
    def _roundtrip(self, content):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sub" / "file"
            write_private(target, content)
            return target.read_bytes()

    def test_private_key_keeps_lf_endings(self):
        self.assertEqual(self._roundtrip(PEM), PEM.encode("utf-8"))

    def test_no_cr_is_introduced(self):
        self.assertNotIn(b"\r", self._roundtrip(PEM))

    def test_existing_crlf_is_not_doubled(self):
        csv_like = "a,b\r\nc,d\r\n"
        self.assertEqual(self._roundtrip(csv_like), csv_like.encode("utf-8"))
        self.assertNotIn(b"\r\r", self._roundtrip(csv_like))

    def test_creates_missing_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c" / "file"
            write_private(target, "x")
            self.assertTrue(target.is_file())

    def test_writes_utf8_content(self):
        self.assertEqual(self._roundtrip("主机名\n"), "主机名\n".encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_newlines -v`
Expected: FAIL — `ImportError: cannot import name 'write_private'`

- [ ] **Step 3: Write the implementation**

Append to `src/termius_export/fsperm.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_newlines tests.test_fsperm -v`
Expected: PASS, 17 tests

- [ ] **Step 5: Commit**

```bash
git add tests/test_newlines.py src/termius_export/fsperm.py
git commit -m "Move the private write path into fsperm and write newlines verbatim

write_text defaults to newline=None, translating every \\n to os.linesep. On
Windows that produced CRLF private keys, which OpenSSH rejects, and turned
hosts.csv into \\r\\r\\n since csv.writer already emits \\r\\n. Byte-level
no-op on POSIX.

Living in fsperm rather than cli makes it testable: cli imports crypto, which
needs pynacl, so no test can import it."
```

---

## Task 6: Route cli.py through fsperm and surface warnings

**Files:**
- Modify: `src/termius_export/cli.py`

- [ ] **Step 1: Import fsperm and alias the moved function**

In `src/termius_export/cli.py`, add to the relative imports:

```python
from . import fsperm
```

Replace the whole `_write_private` function (currently `cli.py:77-81`) with an alias, so the
~8 call sites in this file stay untouched:

```python
#: Moved to fsperm, which owns every platform-dependent filesystem concern. Aliased rather
#: than renamed at each call site to keep this change small.
_write_private = fsperm.write_private
```

`os` is still used elsewhere in the file (`os.umask`), so leave the import alone.

- [ ] **Step 2: Harden the output directory through fsperm**

In `main()`, change:

```python
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)
```

to:

```python
    out_dir.mkdir(parents=True, exist_ok=True)
    fsperm.secure_dir(out_dir)
```

- [ ] **Step 3: Add warnings to the summary**

In `main()`, add a `warnings` key to the `summary` dict, immediately after `"secrets_included"`:

```python
        "secrets_included": not args.no_secrets,
        "warnings": fsperm.warnings(),
```

- [ ] **Step 4: Print warnings in the human summary**

In `_print_human`, insert before the final `if s["verification"]:` block:

```python
    if s.get("warnings"):
        print()
        print("warnings:")
        for w in s["warnings"]:
            print(f"  [WARN] {w}")
```

- [ ] **Step 5: Verify cli.py compiles**

`cli.py` imports `crypto`, which needs `pynacl`, so it cannot be imported here. Check it
compiles instead.

Run: `python3 -m py_compile src/termius_export/cli.py && echo COMPILES`
Expected: `COMPILES`

- [ ] **Step 6: Confirm nothing regressed**

Run: `PYTHONPATH=src python3 -m unittest discover -s tests -v`
Expected: PASS, 24 tests

- [ ] **Step 7: Commit**

```bash
git add src/termius_export/cli.py
git commit -m "Route cli.py filesystem handling through fsperm

Keeps platform branches out of cli.py, and surfaces hardening failures in
both the human summary and --json output instead of dropping them."
```

---

## Task 7: localkey — decode the credential blob

**Files:**
- Modify: `src/termius_export/localkey.py`
- Test: `tests/test_localkey.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_localkey.py`:

```python
"""localKey retrieval.

The blob decoding tests matter because CredentialBlob is raw bytes with no declared encoding.
Rather than assume keytar's UTF-8, the decoder disambiguates using the key's known shape -
base64 of exactly 32 bytes - the same technique that produced the cipher format.
"""

import base64
import sys
import unittest

sys.path.insert(0, "src")

from termius_export.localkey import _decode_credential_blob, _looks_like_local_key

KEY = base64.b64encode(bytes(range(32))).decode("ascii")


class LooksLikeLocalKeyTests(unittest.TestCase):
    def test_accepts_base64_of_exactly_32_bytes(self):
        self.assertTrue(_looks_like_local_key(KEY))

    def test_rejects_base64_of_31_bytes(self):
        self.assertFalse(_looks_like_local_key(base64.b64encode(bytes(31)).decode("ascii")))

    def test_rejects_base64_of_33_bytes(self):
        self.assertFalse(_looks_like_local_key(base64.b64encode(bytes(33)).decode("ascii")))

    def test_rejects_non_base64(self):
        self.assertFalse(_looks_like_local_key("not base64 at all!!"))

    def test_rejects_empty_string(self):
        self.assertFalse(_looks_like_local_key(""))


class DecodeCredentialBlobTests(unittest.TestCase):
    def test_decodes_utf8_blob(self):
        self.assertEqual(_decode_credential_blob(KEY.encode("utf-8")), (KEY, "utf-8"))

    def test_decodes_utf16le_blob(self):
        self.assertEqual(_decode_credential_blob(KEY.encode("utf-16-le")), (KEY, "utf-16-le"))

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(_decode_credential_blob(f"  {KEY}\r\n".encode("utf-8")), (KEY, "utf-8"))

    def test_unrecognised_blob_is_returned_with_an_explicit_label(self):
        value, encoding = _decode_credential_blob(b"garbage")
        self.assertEqual(value, "garbage")
        self.assertIn("unvalidated", encoding)

    def test_does_not_raise_on_undecodable_bytes(self):
        value, encoding = _decode_credential_blob(b"\xff\xfe\x00garbage")
        self.assertIsInstance(value, str)
        self.assertIn("unvalidated", encoding)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: FAIL — `ImportError: cannot import name '_decode_credential_blob'`

- [ ] **Step 3: Write the implementation**

In `src/termius_export/localkey.py`, add `import base64` to the imports (alphabetically first),
and add after the `ACCOUNT` constant:

```python
#: localKey is a NaCl secretbox key: base64 of exactly 32 bytes.
LOCAL_KEY_BYTES = 32

#: Which blob encoding actually worked, per service. Reported in the run summary so the first
#: real Windows run measures this instead of leaving it an assumption.
_LAST_BLOB_ENCODING: dict[str, str] = {}


def _looks_like_local_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == LOCAL_KEY_BYTES
    except Exception:  # noqa: BLE001 - any decoding problem means "not a key"
        return False


def _decode_credential_blob(blob: bytes) -> tuple[str, str]:
    """Decode a Windows CredentialBlob into ``(key, encoding_label)``.

    The blob is raw bytes and Credential Manager declares no encoding. keytar writes UTF-8,
    but that cannot be confirmed without a Windows machine, so rather than assume, candidate
    encodings are disambiguated by the key's known shape - the same "use the known plaintext"
    technique that produced the cipher format. The label is reported in the run summary, so
    the first real Windows run turns this from an assumption into a measurement.
    """
    for label in ("utf-8", "utf-16-le"):
        try:
            candidate = blob.decode(label).strip()
        except UnicodeDecodeError:
            continue
        if _looks_like_local_key(candidate):
            return candidate, label
    return blob.decode("utf-8", errors="replace").strip(), "utf-8 (unvalidated)"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: PASS, 10 tests

- [ ] **Step 5: Commit**

```bash
git add tests/test_localkey.py src/termius_export/localkey.py
git commit -m "Decode the Windows credential blob by validating the key's shape

CredentialBlob is raw bytes with no declared encoding. Rather than assume
keytar's UTF-8, disambiguate candidates by the fact that localKey is base64
of exactly 32 bytes, and report which encoding won."
```

---

## Task 8: localkey — the Credential Manager backend

**Files:**
- Modify: `src/termius_export/localkey.py`
- Test: `tests/test_localkey.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_localkey.py`, before the `if __name__` block:

```python
from termius_export import localkey


class ImportSafetyTests(unittest.TestCase):
    def test_backend_exists(self):
        # ctypes.wintypes raises on non-Windows, so it must never be imported at module
        # scope. If importing this module fails on Linux, the Windows code leaked its guard.
        self.assertTrue(hasattr(localkey, "_from_credential_manager"))

    def test_credential_backend_returns_none_off_windows(self):
        if sys.platform == "win32":
            self.skipTest("Windows has a real Credential Manager")
        self.assertIsNone(localkey._from_credential_manager("Termius"))

    def test_candidate_services_still_contains_the_measured_windows_service(self):
        # Measured on a real Windows install: target=Termius/localKey
        self.assertIn("Termius", localkey.CANDIDATE_SERVICES)


@unittest.skipUnless(sys.platform == "win32", "requires Windows Credential Manager")
class LiveCredentialManagerTests(unittest.TestCase):
    def test_reads_the_termius_local_key(self):
        value = localkey._from_credential_manager("Termius")
        self.assertIsNotNone(value, "no Termius/localKey credential found")
        self.assertTrue(
            _looks_like_local_key(value),
            f"credential decoded to something that is not a 32-byte key: {len(value)} chars",
        )

    def test_find_local_key_reports_its_source(self):
        key, source = localkey.find_local_key()
        self.assertTrue(_looks_like_local_key(key))
        self.assertIn("Credential Manager", source)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: FAIL — `AttributeError: module 'termius_export.localkey' has no attribute '_from_credential_manager'`.
`LiveCredentialManagerTests` reports as skipped on Linux.

- [ ] **Step 3: Write the implementation**

In `src/termius_export/localkey.py`, add after `_from_macos_keychain`:

```python
def _from_credential_manager(service: str) -> str | None:
    """Windows: read the generic credential keytar writes.

    ``ctypes`` is used rather than a PowerShell subprocess because ``cmdkey`` cannot print a
    credential blob - reading one needs ``CredReadW`` either way, and going through PowerShell
    would mean compiling C# at runtime via ``Add-Type``: slow, frequently flagged by
    antivirus, and blocked outright by some execution policies. The ``keyring`` package was
    also rejected, since it would rewrite the Linux and macOS paths that are already verified.

    Everything ctypes-related is imported inside this function on purpose: ``ctypes.wintypes``
    raises on non-Windows, so importing it at module scope would break the module everywhere
    else.
    """
    if sys.platform != "win32":
        return None

    import ctypes
    import ctypes.wintypes

    CRED_TYPE_GENERIC = 1

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", ctypes.wintypes.DWORD),
            ("dwHighDateTime", ctypes.wintypes.DWORD),
        ]

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
            ("TargetName", ctypes.wintypes.LPWSTR),
            ("Comment", ctypes.wintypes.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", ctypes.wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", ctypes.wintypes.DWORD),
            ("AttributeCount", ctypes.wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", ctypes.wintypes.LPWSTR),
            ("UserName", ctypes.wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.CredReadW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    advapi32.CredReadW.restype = ctypes.wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    # keytar's target format. Measured on a real install: target=Termius/localKey.
    target = f"{service}/{ACCOUNT}"
    pcred = ctypes.POINTER(CREDENTIAL)()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        return None

    try:
        cred = pcred.contents
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
    finally:
        advapi32.CredFree(pcred)

    value, encoding = _decode_credential_blob(blob)
    if not value:
        return None
    _LAST_BLOB_ENCODING[service] = encoding
    return value
```

Register the backend in `_available_backends`, leaving the existing two entries untouched:

```python
def _available_backends() -> list[tuple[str, object]]:
    backends: list[tuple[str, object]] = []
    if shutil.which("secret-tool"):
        backends.append(("secret-tool", _from_secret_tool))
    if sys.platform == "darwin" and shutil.which("security"):
        backends.append(("macOS keychain", _from_macos_keychain))
    if sys.platform == "win32":
        # advapi32 ships with Windows, so this backend is always available.
        backends.append(("Windows Credential Manager", _from_credential_manager))
    return backends
```

Finally, make `find_local_key` report the encoding. Replace the success `return` inside the
service loop:

```python
    for service in CANDIDATE_SERVICES:
        for backend, fn in backends:
            value = fn(service)
            if value:
                detail = f"{backend} (service={service}, account={ACCOUNT}"
                encoding = _LAST_BLOB_ENCODING.get(service)
                if encoding:
                    detail += f", blob encoding={encoding}"
                return value, detail + ")"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: PASS, 13 tests, 2 skipped on Linux

- [ ] **Step 5: Confirm the module still imports on Linux**

The single biggest risk in this task is `ctypes.wintypes` escaping its guard.

Run: `PYTHONPATH=src python3 -c "import termius_export.localkey; print('IMPORT OK')"`
Expected: `IMPORT OK`

- [ ] **Step 6: Commit**

```bash
git add tests/test_localkey.py src/termius_export/localkey.py
git commit -m "Read localKey from Windows Credential Manager via ctypes

Measured on a real install: Termius stores it as a generic credential under
target 'Termius/localKey', keytar's {service}/{account} convention. The
service name was already in CANDIDATE_SERVICES, so only a backend is new.

All ctypes imports live inside the function because ctypes.wintypes raises on
non-Windows."
```

---

## Task 9: Platform-appropriate not-found messages

**Files:**
- Modify: `src/termius_export/localkey.py`, `src/termius_export/source.py`
- Test: `tests/test_localkey.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_localkey.py`, before the `if __name__` block:

```python
class NotFoundMessageTests(unittest.TestCase):
    def test_windows_message_does_not_mention_linux_package_managers(self):
        message = localkey._not_found_message(["Windows Credential Manager"], platform="win32")
        for noise in ("dnf", "apt", "pacman", "secret-tool", "libsecret"):
            self.assertNotIn(noise, message)

    def test_windows_message_points_at_credential_manager(self):
        message = localkey._not_found_message(["Windows Credential Manager"], platform="win32")
        self.assertIn("cmdkey", message)
        self.assertIn("--local-key-file", message)

    def test_windows_message_lists_the_target_form(self):
        message = localkey._not_found_message(["Windows Credential Manager"], platform="win32")
        self.assertIn("Termius/localKey", message)

    def test_posix_message_is_unchanged(self):
        message = localkey._not_found_message(["secret-tool"], platform="linux")
        self.assertIn("secret-tool", message)
        self.assertIn("termius-app", message)
        self.assertIn("--local-key-file", message)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: FAIL — `AttributeError: module 'termius_export.localkey' has no attribute '_not_found_message'`

- [ ] **Step 3: Write the implementation**

In `src/termius_export/localkey.py`, add before `find_local_key`:

```python
def _not_found_message(backend_names: list[str], platform: str | None = None) -> str:
    """The "a backend works but holds no key" message, per platform.

    The POSIX text is kept verbatim: Linux is the verified platform and macOS is validated on
    a separate track, so neither may drift as part of a Windows change.
    """
    platform = sys.platform if platform is None else platform
    tried = ", ".join(backend_names)

    if platform == "win32":
        targets = ", ".join(f"{s}/{ACCOUNT}" for s in CANDIDATE_SERVICES)
        return (
            f"A credential backend is available ({tried}) but it holds no Termius localKey.\n"
            f"Tried target names: {targets}.\n"
            "\n"
            "Most likely causes:\n"
            "  - Termius has never been launched on this machine (the key is created on first run)\n"
            "  - the export is running as a different Windows user than the one that runs Termius\n"
            "  - Termius stores it under a target name not in the list above\n"
            "\n"
            "Check by hand, in PowerShell:\n"
            "  cmdkey /list | Select-String termius\n"
            "\n"
            "If the target name differs from those tried above, please report it. Otherwise\n"
            "read the key out yourself and pass it in via --local-key-file."
        )

    return (
        f"A keyring client is available ({tried}) but it holds no Termius localKey.\n"
        f"Tried service names: {', '.join(CANDIDATE_SERVICES)} with account={ACCOUNT}.\n"
        "\n"
        "Most likely causes:\n"
        "  - Termius has never been launched on this machine (the key is created on first run)\n"
        "  - the keyring is locked; unlock it and retry\n"
        "  - Termius stores it under a service name not in the list above\n"
        "\n"
        "Check by hand:\n"
        "  secret-tool lookup service termius-app account localKey        # Linux\n"
        "  security find-generic-password -s Termius -a localKey -w       # macOS\n"
        "\n"
        "Then pass the value via --local-key-file."
    )
```

Then replace the tail of `find_local_key` — the `tried = ", ".join(...)` line and the
`raise LocalKeyNotFound(...)` that follows it — with:

```python
    raise LocalKeyNotFound(_not_found_message([name for name, _ in backends]))
```

- [ ] **Step 4: Add the Windows path to source.py's message**

In `src/termius_export/source.py`, change the `IndexedDbNotFound` raise to include Windows:

```python
    raise IndexedDbNotFound(
        f"No IndexedDB found under {p}. Point --data-dir at the Termius data directory, e.g.\n"
        "  Linux (snap):  ~/snap/termius-app/current/.config/Termius\n"
        "  Linux (other): ~/.config/Termius\n"
        "  macOS:         ~/Library/Application Support/Termius\n"
        "  Windows:       %APPDATA%\\Termius"
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m unittest tests.test_localkey -v`
Expected: PASS, 17 tests, 2 skipped on Linux

- [ ] **Step 6: Verify source.py compiles**

`source.py` imports `ccl_chromium_reader`, unavailable here.

Run: `python3 -m py_compile src/termius_export/source.py && echo COMPILES`
Expected: `COMPILES`

- [ ] **Step 7: Commit**

```bash
git add tests/test_localkey.py src/termius_export/localkey.py src/termius_export/source.py
git commit -m "Give Windows its own not-found message

The old message told Windows users to run 'dnf install libsecret'. POSIX text
is kept verbatim so the verified Linux path and the separately-validated
macOS path do not drift as part of a Windows change."
```

---

## Task 10: Full suite, then correct the documentation

**Files:**
- Modify: `README.md`, `CLAUDE.md`

- [ ] **Step 1: Run the full suite**

Run: `PYTHONPATH=src python3 -m unittest discover -s tests -v`
Expected: 41 tests, 0 failures, 0 errors, 2 skipped on Linux.

- [ ] **Step 2: Confirm every module compiles**

Run: `python3 -m compileall -q src/termius_export && echo ALL COMPILE`
Expected: `ALL COMPILE`

- [ ] **Step 3: Correct README.md**

Replace the first bullet of "Limitations" (`README.md:146-147`) with:

```markdown
- Verified on Linux (snap install) and Windows. The macOS branch follows platform conventions
  but has not been exercised on real hardware
```

Add to "If the key cannot be read automatically", after the existing `secret-tool` / `security`
code block:

````markdown
On Windows the key lives in Credential Manager under the target `Termius/localKey`. The tool
reads it directly; to confirm it exists:

```powershell
cmdkey /list | Select-String termius
```

`cmdkey` lists targets but never prints the blob, so there is no one-line way to dump the key
by hand. If the automatic read fails, report the target name it shows.
````

Add to "Security", after the first bullet:

```markdown
- On Windows, POSIX modes do not apply: `os.chmod` there can only toggle the read-only
  attribute. The output directory is restricted with `icacls` to the current user's SID and
  files inherit it. If that fails the run warns rather than letting you assume the keys are
  protected
```

- [ ] **Step 4: Correct CLAUDE.md**

Replace the first bullet of "Known limitations" with:

```markdown
- Verified on Linux (snap install) and Windows. The macOS path/keyring branch follows platform
  conventions but has not been exercised on real hardware
```

Add `fsperm.py` to the architecture table, after the `localkey.py` row:

```markdown
| `fsperm.py` | Platform-dependent filesystem writes and permission hardening |
```

Rename the "Three traps" heading to "Four traps" and append:

````markdown
### 4. Windows needs three separate things, and two of them fail silently

Measured on a real install, not assumed:

- **The keyring service name is `Termius`**, and Credential Manager's target is
  `Termius/localKey` — keytar's `{service}/{account}` form. `CANDIDATE_SERVICES` already
  contained `Termius`, so only a backend was needed.
- **`os.chmod` is a no-op on Windows.** It can only toggle the read-only attribute, so `0600`
  on a private key silently protects nothing. `fsperm.py` uses `icacls` with the user's
  **SID** — well-known principal names are localized, so an English literal fails on a
  non-English Windows.
- **`Path.write_text` translates newlines.** The default `newline=None` turns every `\n` into
  `os.linesep`, producing CRLF private keys and, because `csv.writer` already emits `\r\n`, a
  `hosts.csv` full of `\r\r\n`. `fsperm.write_private` passes `newline="\n"`.

The last two are invisible on Linux, where `chmod` works and `os.linesep` is already `\n`.
Testing on the development platform cannot surface them.

**`Local State`'s `os_crypt.encrypted_key` is not the localKey.** It base64-decodes to a
`DPAPI` prefix and is Chromium's own cookie/Local-Storage key, present in every Electron app.
Do not investigate it again.

One more, measured with the real parser: an **unquoted `IdentityFile` path containing a space
makes `ssh` reject the entire config file** (`keyword identityfile extra arguments at end of
line`), not just that host. `_quote_path` in `writers/openssh.py` quotes exactly those paths.
````

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Document Windows support and record the traps

The old text claimed a Windows branch existed and was merely unverified; no
such branch existed. macOS keeps its unverified status verbatim, since this
change produces no evidence about it."
```

---

## Task 11: Manual Windows verification

The only task that cannot run on the development machine. Performed by the user; the procedure
and expected output go in the handoff message.

- [ ] **Step 1: User runs the test suite on Windows**

The two `LiveCredentialManagerTests` that skip on Linux must actually run and pass there.

- [ ] **Step 2: User runs a full export against a copy of the data directory**

- [ ] **Step 3: Record the measured blob encoding**

The `key from:` line reports which encoding Credential Manager actually used. Update the
docstring of `_decode_credential_blob` to state the measured result instead of describing it as
undetermined.

- [ ] **Step 4: Update the verification claim to match what was exercised**

Only after the run passes. Name the Windows version and the scope covered.

---

## Self-Review

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| Defect 1 — no Windows keyring backend | 7, 8 |
| Defect 2 — chmod hardening is a no-op | 3, 4, 6 |
| Defect 3 — unquoted IdentityFile | 1, 2 |
| Defect 4 — newline translation | 5, 6 |
| `fsperm.py` new module | 3, 4, 5 |
| SID rather than localized principal name | 3 |
| Directory ACL with inheritance, not per-file | 4 |
| Memoized `secure_dir` | 4 |
| `secure_file` is a deliberate Windows no-op | 4 |
| Warnings surfaced to stderr and `--json` | 3, 6 |
| Blob encoding disambiguation by known shape | 7 |
| Encoding reported in the summary | 8 |
| `CANDIDATE_SERVICES` unchanged | 8 (asserted in test) |
| Windows not-found message, POSIX text verbatim | 9 |
| Windows path in `source.py` message | 9 |
| POSIX invariant | 1, 2, 5 (explicit byte-level tests); 4 (POSIX mode tests) |
| stdlib unittest, runnable on Windows | every test task |
| Docs corrected, macOS not upgraded | 10 |
| Manual Windows verification | 11 |

No spec requirement is unassigned.

**Type consistency:** `_quote_path`, `_parse_sid`, `_icacls_args`, `_current_user_sid`,
`_harden_dir`, `secure_dir`, `secure_file`, `write_private`, `warnings`, `IS_WINDOWS`,
`_secured`, `_looks_like_local_key`, `_decode_credential_blob`, `_from_credential_manager`,
`_not_found_message`, `_LAST_BLOB_ENCODING` and `LOCAL_KEY_BYTES` are each defined in exactly
one task and referenced with identical names and signatures thereafter. The Task 4 memoization
test substitutes `fsperm._harden_dir` (Task 4) and clears `fsperm._secured` (Task 3); both
exist by then. `tests/test_newlines.py` imports `write_private` from `fsperm`, defined in
Task 5 — never from `cli`, which cannot be imported without `pynacl`.

**Test count:** 7 (quoting) + 12 (fsperm) + 5 (newlines) + 17 (localkey) = 41; 2 skipped on
Linux, 3 skipped on Windows (`PosixSecureTests`).

**Placeholder scan:** No TBD, TODO, "add error handling", or "similar to Task N". Every code
step contains complete code.
