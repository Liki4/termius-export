# Windows support — design

Date: 2026-08-12
Status: approved, not yet implemented

## Problem

The tool does not run on Windows. Three defects, in descending severity:

1. **`localkey.py` has no Windows backend.** `_available_backends()` registers only
   `secret-tool` (Linux) and `security` (macOS). On Windows both are absent, so the list is
   empty and `find_local_key()` raises immediately. The raised message then instructs the user
   to run `dnf install libsecret` / `apt install libsecret-tools`, which is actively misleading
   on Windows.

2. **Permission hardening silently does nothing.** `os.umask(0o077)`, `chmod(0o700)` and
   `chmod(0o600)` in `cli.py` do not raise on Windows, but `os.chmod` there can only toggle the
   read-only attribute — every other bit is ignored. Exported private keys inherit the parent
   directory's ACL. The security posture documented in README ("output directory 0700, private
   keys 0600") is therefore false on Windows.

3. **`IdentityFile` paths are unquoted.** `openssh.py:48` interpolates an absolute path
   directly. On Windows the path is frequently `C:\Users\First Last\...`; an unquoted space
   breaks the directive.

4. **Every output file is newline-translated on Windows, corrupting some of them.**
   `cli.py::_write_private` calls `path.write_text(content, encoding="utf-8")`. `write_text`
   defaults to `newline=None`, which translates every `\n` to `os.linesep` — `\r\n` on Windows.
   Consequences, in descending severity:

   - **Private keys become CRLF PEM.** OpenSSH is strict about private key framing; this is
     the difference between an export that works and one that produces unusable keys.
   - **`hosts.csv` is doubly translated.** `csv.writer` already emits `\r\n`, so the extra
     translation yields `\r\r\n` and a malformed file.
   - `sshconfig` and `known_hosts` become CRLF. Windows OpenSSH mostly tolerates this, but
     the files are also likely to be copied to a POSIX host.

   This defect was found while checking the environment for the plan, not from the earlier
   read-through — it is invisible on Linux, where `os.linesep` is already `\n`, so no amount
   of testing on the development platform would surface it.

Additionally, README.md:146 and CLAUDE.md both claim the "Windows branch follows platform
conventions but has not been exercised on real hardware". This is inaccurate: there is no
Windows branch to exercise. The documentation must be corrected regardless of the code.

## What was measured, not assumed

Run on a real Windows machine with Termius installed (Chinese-localized Windows):

```
> cmdkey /list | Select-String -Pattern "termius" -Context 3,3
      目标: LegacyGeneric:target=Termius/localKey
      类型: 普通
      用户: localKey
```

```
> Get-ChildItem "$env:APPDATA\Termius" -Force
IndexedDB, Local State, Preferences, ... (directory exists at the expected location)
```

```
> (Get-Content "$env:APPDATA\Termius\Local State" -Raw | ConvertFrom-Json).os_crypt
encrypted_key : RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6w...
```

Three conclusions:

- **Termius on Windows stores `localKey` in Credential Manager**, as a generic credential with
  `TargetName = "Termius/localKey"` and `UserName = "localKey"`. That is keytar's
  `{service}/{account}` convention. The service name is `Termius`, which is **already** the
  second entry of `CANDIDATE_SERVICES`, so the existing service-name candidate loop needs no
  change — only a new backend function.
- **The data directory needs no work.** `%APPDATA%\Termius` contains `IndexedDB`, so
  `locate_leveldb`'s third candidate (`source.py:59`) hits and `cli.py:22`'s auto-detection
  resolves via `expanduser()`/`USERPROFILE`.
- **`os_crypt.encrypted_key` is a red herring.** It base64-decodes to a `DPAPI` prefix; this is
  Chromium's own key for cookie and Local Storage encryption and is present in every
  Electron app. It is unrelated to Termius's field-level secretbox encryption. Recorded here so
  it is not investigated a second time.

## Scope

**Windows only.** Linux (Fedora) is the development platform and is already confirmed working;
macOS is validated separately and independently of this change.

This gives the change a hard invariant, stated once here and enforced throughout:

> **POSIX behaviour must be unchanged.** Not "probably fine" — unchanged. Every existing code
> path on Linux and macOS must produce byte-identical output and perform the same syscalls.

The invariant is what makes the narrow scope safe. Linux does not need re-verification because
nothing about it changes, and macOS's independent validation is not invalidated by this work.
Concretely: `_from_macos_keychain` is not touched, the existing Linux/macOS not-found message is
not touched, and `fsperm`'s POSIX branch performs exactly the `chmod` calls `cli.py` performs
today. New behaviour is reachable only under `sys.platform == "win32"`.

## Non-goals

- Refactoring `localkey.py` onto the `keyring` package. It would unify three platforms, but it
  adds a dependency and would rewrite the macOS and Linux paths — violating the invariant above.
- Backfilling tests for `crypto` / `normalize` / existing writers. Out of scope for this change.
- Supporting hardware-backed keys (Windows TPM). The private key never leaves the hardware.
- Any macOS change, including to its not-found message. Validated on a separate track.

## Design

### Module layout

| File | Change |
|---|---|
| `fsperm.py` | **new** — platform-dependent permission hardening, nothing else |
| `localkey.py` | add `_from_credential_manager`; add a Windows branch to the not-found message, leaving the existing POSIX text verbatim |
| `cli.py` | delegate to `fsperm`; carry a `warnings` list into the summary |
| `writers/openssh.py` | quote `IdentityFile` when the path contains whitespace |
| `source.py` | add the Windows path to the `IndexedDbNotFound` message |

`crypto.py`, `normalize.py`, `model.py` and all other writers are untouched.

`fsperm.py` exists so that `cli.py` does not accumulate `sys.platform` branches. It matches the
repository's existing convention of one file per responsibility.

### Credential Manager backend

```python
def _from_credential_manager(service: str) -> str | None:
    if sys.platform != "win32":
        return None
    target = f"{service}/{ACCOUNT}"
    # ctypes -> advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, byref(pcred))
    # read CredentialBlob[:CredentialBlobSize], then CredFree(pcred)
```

Registered in `_available_backends()` alongside the existing two. `CANDIDATE_SERVICES` is
unchanged.

Chosen over a PowerShell subprocess (which would need runtime C# compilation via `Add-Type` —
slow, antivirus-prone, blocked by execution policy) and over adding the `keyring` dependency.
`ctypes` is stdlib and the project currently carries only two dependencies, one of which is
already a GitHub-only git URL that is awkward to install on Windows.

**Blob encoding is undeclared.** `CredentialBlob` is raw bytes. keytar writes UTF-8, but we
cannot confirm from Linux that Termius uses keytar. Rather than guess, disambiguate using the
key's known shape — the same technique the project used to reverse-engineer the cipher format:
`localKey` is base64 of exactly 32 bytes.

1. Decode the blob as UTF-8, strip, test that it base64-decodes to exactly 32 bytes.
2. If that fails, repeat with UTF-16LE.
3. If neither yields a 32-byte key, return the UTF-8 attempt and let
   `Decryptor.__post_init__`'s existing length check raise.

The encoding that succeeded is appended to the returned source description, so it surfaces on
the `key from:` line of the summary. The first real Windows run therefore reports which encoding
Termius actually uses instead of leaving it as an assumption.

### Permission hardening

`fsperm` exposes two functions; POSIX behaviour is byte-for-byte what `cli.py` does today.

```python
secure_dir(path)             # POSIX: chmod 0700      Windows: icacls
secure_file(path, mode)      # POSIX: chmod <mode>    Windows: no-op, by design
```

`secure_dir` memoizes by path on both platforms; on POSIX this is only a redundant-syscall
saving and produces an identical end state, on Windows it avoids repeated process spawns.

`secure_file` is deliberately a no-op on Windows rather than a per-file `icacls` call: the
file already inherits the directory's restrictive ACL, so the call would be redundant. Public
keys and `known_hosts` (mode `0644`) therefore end up user-only on Windows, which is harmless —
they contain no secrets and nothing reads them from another account.

On Windows the ACL is set **on the directory, with inheritance removed**, and files created
inside inherit it:

```
icacls "<dir>" /inheritance:r /grant:r *<SID>:(OI)(CI)F
```

Setting the ACL per-file would spawn one `icacls` process per exported key. Securing the
directory once and letting `(OI)(CI)` inheritance apply is both correct for Windows ACL
semantics and far cheaper. `secure_dir` memoizes by path because `cli.py::_write_private`
currently re-hardens the parent directory on every single write.

**The principal is a SID, not a name.** The test machine is Chinese-localized; well-known
principal names in `icacls` are localized on such systems, so an English literal would fail.
The current user's SID comes from `whoami /user /fo csv /nh` and is passed with icacls's `*`
prefix, which sidesteps localization entirely.

If `icacls` fails or is missing, the failure is reported — never swallowed:

- a warning to stderr, and
- an entry in a `warnings` list added to the summary dict, so `--json` consumers see it too.

This follows the repository's existing stance that a silently wrong result is worse than a loud
failure.

### Newline handling

`_write_private` passes `newline="\n"` to `write_text`, disabling translation so file content
is written verbatim.

This satisfies the POSIX invariant exactly rather than approximately: on Linux and macOS
`os.linesep` is already `\n`, so `newline=None` and `newline="\n"` produce identical bytes. The
change is therefore a no-op on the verified platforms and a correctness fix on Windows.

Writers keep emitting `\n` (and `csv.writer` keeps emitting its own `\r\n`); the fix belongs at
the single point where bytes reach the disk, not spread across six writers.

### IdentityFile quoting

`openssh.py` quotes the path only when it contains whitespace. Quoting unconditionally would
change existing Linux output for every user with no benefit; quoting conditionally leaves
current output byte-identical unless a path genuinely contains a space.

### Documentation corrections

- README.md:146 and the CLAUDE.md limitations section: remove the claim that a Windows branch
  exists and is merely unverified.
- README's "If the key cannot be read automatically" section: add the Windows lookup and the
  `--local-key-file` escape hatch.
- CLAUDE.md: extend the "Three traps" section with the Windows findings — service name
  `Termius`, `{service}/{account}` target format, the `os_crypt` red herring, and the fact that
  `os.chmod` is a no-op on Windows.
- Verification level is written to match reality: "unverified on Windows" until the real run
  passes, then updated to name the exact Windows version and install method tested, and the
  scope of what was exercised.

The existing sentence bundles macOS and Windows together ("macOS and Windows branches follow
platform conventions but have not been exercised"). Rewriting it must split the two rather than
upgrade both: the Windows half becomes accurate for the first time, while **macOS keeps its
current unverified status verbatim** — it is validated on a separate track and this change
provides no evidence about it.

## Verification

Split by what each side can actually falsify.

**POSIX regression** is handled by construction, not by testing: the invariant in *Scope* means
no Linux or macOS code path changes. The one place this needs active checking is
`writers/openssh.py`, which is shared code rather than a platform branch — the quoting predicate
must leave every space-free path untouched. That is directly testable on Linux and is covered
below.

Runnable on the Linux development machine:

- `ruff check` and module import on all touched files.
- New `tests/` — the repository's first — covering only platform-independent pure logic:
  blob encoding disambiguation given synthetic bytes, `icacls` argument construction, the
  quoting predicate including its no-change-without-spaces guarantee, and verbatim newline
  writing.

  **Written against stdlib `unittest`, not pytest.** The development machine has no pytest, no
  ruff and no nix, and neither `pynacl` nor `ccl_chromium_reader` is importable there — but
  `localkey`, `model` and every writer import with stdlib alone, which is what makes this
  possible. The payoff is larger than avoiding an install: the same suite runs unmodified on
  the Windows test machine with no setup, so the pure Windows logic gets exercised natively on
  Windows rather than only in simulation from Linux.

  Tests that need a real Windows API call are guarded with
  `@unittest.skipUnless(sys.platform == "win32", ...)`, so they are reported as skipped on
  Linux and actually run for the user.
- A synthetic `Model` written through `OpenSshWriter`, then read back with a real `ssh -G`
  invocation. This exercises the quoting change end to end, since `ssh` is present locally.
  Note the development machine has no Termius data and no `secret-tool`, so a real-data export
  cannot be run here; the synthetic model is what makes the writer path testable regardless.

Only verifiable on Windows, by the user:

- Credential Manager read, and which blob encoding was used.
- `icacls` actually restricting the exported keys.
- Full end-to-end export against a copy of `%APPDATA%\Termius`.

Tests deliberately do not cover `crypto` / `normalize` / existing writers; that is separate
work.

## Risks

- The `CREDENTIAL` struct must be laid out correctly for the target architecture, and
  `CredFree` must be called on the returned pointer. Getting this wrong leaks or crashes.
- `whoami` output parsing is a small surface but is the only place a localized system could
  still bite; the CSV format (`/fo csv /nh`) is stable and not localized in its structure.
- The blob-encoding fallback is defensive code for a case that may not occur. It is ~6 lines
  and its outcome is reported, so it pays for itself by turning an assumption into a
  measurement.
