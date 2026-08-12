# termius-export

Decrypts Termius's local data offline and converts hosts, SSH keys, port forwards and proxy
settings into configuration for other SSH clients.

**Termius does not need to be running.** This tool never launches it and never opens a debug
port — it reads the IndexedDB straight off disk, so it also works on a cold backup directory.

---

## Quick start

```bash
nix develop                       # or: pip install -e .
python -m termius_export --out out
```

Default behaviour: auto-detect the Termius data directory, read the decryption key from the OS
keyring, emit every format, then self-verify.

```bash
python -m termius_export --format openssh,tabby --no-secrets
python -m termius_export --data-dir ~/termius-backup/Termius --out out
```

---

## Architecture

Four stages. Writers **never** touch Termius's table layout:

```
source.py     LevelDB          ──►  raw tables (list of dicts)
crypto.py     per-field secretbox decryption
normalize.py  Termius schema   ──►  client-agnostic model
writers/      model            ──►  per-client config
verify.py     read outputs back, compare against the model
```

| File | Responsibility |
|---|---|
| `source.py` | Read Chromium IndexedDB, deduplicate records |
| `crypto.py` | XSalsa20-Poly1305 decryption, version-header validation |
| `localkey.py` | Fetch `localKey` from the platform keyring |
| `fsperm.py` | Platform-dependent filesystem writes and permission hardening |
| `normalize.py` | Resolve Termius entity references, produce a `Model` |
| `model.py` | Dataclasses for the intermediate model |
| `writers/` | One writer per target client |
| `verify.py` | Self-verification of generated output |

Adding a client means adding one writer file. You should never need to re-read Termius's
internals again.

---

## Cipher format

Field-level encryption:

```
base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305(ciphertext + MAC) )
```

Standard NaCl secretbox with a two-byte version header prepended. The key is the base64-decoded
`localKey` from the OS keyring — 32 bytes.

**This was reverse-engineered, not documented.** See *Reverse-engineering method* below.

Two rules enforced in `crypto.py`:

1. **Detect encrypted fields by the version header**, never by a "looks like base64" heuristic.
2. **Raise on an unknown header** instead of silently skipping. Only `0401` has been observed;
   anything else means Termius changed schemes, and no output from that run should be trusted.

---

## Four traps

All four were hit during development. Don't rediscover them.

### 1. LevelDB holds multiple generations of the same record

Reading LevelDB directly returns historical versions. On one real machine the `hosts` table held
52 raw records for 13 actual hosts.

`ccl_chromium_reader`'s `live_only=True` **does not help** — it filters LevelDB-level tombstones,
and all of these records are "live" at that level.

The fix: **deduplicate by the business primary key `id`, keeping the row with the greatest
`updated_at`** (`source.py::_dedup_latest`). Validate by comparing post-dedup counts against what
the application UI shows, table by table — all six should match exactly.

Skip this and you emit four times as many host entries as the user has.

### 2. An empty string is a valid decryption result, not a failure

When a host has no name, `label` holds an **encrypted empty string**.

A reference implementation wrote `if (!decrypted || ...) return ciphertext;`. An empty string is
falsy, so successfully decrypted empty labels were treated as failures and the raw ciphertext was
returned. Symptom: a few host names show up as base64 gibberish, and no amount of tuning the
heuristic fixes it.

The same bug inflates the "hosts with a password" count, because an empty password's ciphertext
string is truthy.

**Test with `is None`, never for truthiness.**

### 3. The keyring service name depends on how Termius was installed

Termius uses the **executable name** as the keyring service name:

| Install | service |
|---|---|
| Linux snap | `termius-app` |
| macOS | `Termius` |

Looking up `Termius` on a snap install finds nothing. `localkey.py` tries a list of candidates.

Check by hand:

```bash
secret-tool lookup service termius-app account localKey        # Linux
security find-generic-password -s Termius -a localKey -w       # macOS
```

---

### 4. Windows needs four separate things, and none of them show up on Linux

Measured on a real install, not assumed:

- **The keyring service name is `Termius`**, and Credential Manager's target is
  `Termius/localKey` — keytar's `{service}/{account}` form. `CANDIDATE_SERVICES` already
  contained `Termius`, so only a backend was needed, not a new service name.
- **`os.chmod` is a no-op on Windows.** It can only toggle the read-only attribute, so `0600`
  on a private key silently protects nothing. `fsperm.py` uses `icacls` with the user's
  **SID** — well-known principal names are localized, so an English literal fails on a
  non-English Windows.
- **`Path.write_text` translates newlines.** The default `newline=None` turns every `\n` into
  `os.linesep`, producing CRLF private keys and, because `csv.writer` already emits `\r\n`, a
  `hosts.csv` full of `\r\r\n`. `fsperm.write_private` passes `newline="\n"`.
- **`subprocess(text=True)` decodes with the locale ANSI codepage, not UTF-8.** On a Chinese
  Windows that is GBK. `slug()` keeps CJK characters — Python's `\w` is Unicode-aware — so a
  Chinese Termius label becomes a Chinese ssh alias, `ssh -G` echoes it back as the UTF-8
  bytes we wrote, and GBK cannot decode them. The failure is nasty: `UnicodeDecodeError` is
  raised *inside subprocess's reader thread*, so `stdout` is silently left as `None` and the
  real traceback is `'NoneType' object has no attribute 'splitlines'` somewhere unrelated.

  `verify.py::_run` decodes as UTF-8 with `errors="replace"`, matching what we wrote.
  `fsperm`'s calls deliberately do **not**: `whoami` and `icacls` are Windows console programs
  that emit the console codepage, so they keep the locale default and only add
  `errors="replace"`.

The last three are invisible on Linux, where `chmod` works, `os.linesep` is already `\n`, and
the locale is UTF-8. Testing on the development platform cannot surface them.

One more, measured with the real parser: an **unquoted `IdentityFile` path containing a space
makes `ssh` reject the entire config file** (`keyword identityfile extra arguments at end of
line`), not merely that one host. `_quote_path` in `writers/openssh.py` quotes exactly those
paths, and leaves every space-free path byte-identical.

**`Local State`'s `os_crypt.encrypted_key` is not the localKey.** It base64-decodes to a
`DPAPI` prefix and is Chromium's own cookie / Local-Storage key, present in every Electron
app. Do not investigate it again.

---

## Tests

`tests/` uses the standard library's `unittest`, deliberately — not pytest.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Two reasons. The suite needs no install, and `localkey`, `model`, `fsperm` and every writer
import with stdlib alone, so it runs on a bare Python without `pynacl` or
`ccl_chromium_reader`. More importantly it runs unmodified **on Windows**, so the pure Windows
logic is exercised natively rather than only simulated from Linux.

Tests requiring a real Windows API call are guarded with
`@unittest.skipUnless(sys.platform == "win32", ...)`.

**Never import `cli`, `crypto` or `source` from a test** — they pull `pynacl` /
`ccl_chromium_reader` and will fail to import on a bare checkout. This is why
`write_private` lives in `fsperm` rather than `cli`.

## Writer plugin interface

```python
class MyWriter:
    name = "myclient"
    title = "MyClient config"
    verified = "roundtrip"          # see below

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]:
        ...
```

`ctx.key_path(host.key)` yields the absolute path of the private key on disk;
`ctx.include_secrets` decides whether plaintext passwords are written.

### The `verified` field — the most important convention here

| Value | Meaning |
|---|---|
| `roundtrip` | Output has been **read back and validated** by the target client or its official parser |
| `upstream-source` | Fields follow the target client's **type definitions in its own source code**, but no import round-trip was performed |
| `unverified` | Guessed from documentation or experience |

**This repository does not ship `unverified` writers.** A config file that is quietly wrong is
worse than no config file at all — someone will point it at a production host.

Labelling this honestly is non-negotiable. `verify.py` reports Tabby's round-trip check as
`skipped` rather than `pass` for exactly this reason.

### Adding a writer

1. **Get a source of truth first.** Either:
   - export a real config file from the target client (best), or
   - read the target client's own type definitions (acceptable — label `upstream-source`).

   If you have neither, don't write the writer.

2. Create a module under `writers/`. In the module docstring, **cite the source of truth
   precisely** (repository path, file, type name). See `tabby.py` for the pattern.

3. Register it in `WRITERS` in `writers/__init__.py`.

4. Add an offline check to `verify.py`. Even a structural check is worth having; if a round-trip
   is impossible offline, return `passed=None` explicitly.

---

## Verification strategy

**Anything that can be falsified locally must actually be run**, not eyeballed.

| Format | How it is verified |
|---|---|
| OpenSSH | `ssh -G -F <file> <alias>` — let ssh itself parse it, then compare its resolved hostname/port/user per host |
| JSON | `json.load` round-trip, compare host and key counts |
| CSV | `csv.DictReader` round-trip, compare addresses row by row |
| Tabby | Structural check (entry count, quote balance); round-trip import reported as `skipped` |
| Termix | Schema check against `normalizeImportedHost`'s contract (required `ip`, `authType` and `tunnelType` domains); round-trip reported as `skipped` |
| known_hosts | `ssh-keygen -F <host> -f <file>` per entry — OpenSSH's own known_hosts parser |
| Private keys | `ssh-keygen -l -f` on every emitted key, confirming they are real, parseable keys |

Two traps in that table, both found by a 213-host real-world export rather than by reading:

- **`ssh -G` lower-cases the hostname.** Comparing it case-sensitively against the model
  reports every host with an uppercase address as a mismatch. DNS is case-insensitive.
- **`ssh-keygen -l -f <private>` silently falls back to `<private>.pub`.** Any test of the
  private-key path must delete the `.pub` first, or it proves nothing. This is how the
  passphrase-protected PKCS#1 PEM case stayed hidden: those keys encrypt the public modulus
  too, so without the `.pub` ssh-keygen reports `is not a key file` — the same message as for
  genuine corruption. `_is_encrypted_pem` separates them, and such keys are reported as
  **skipped**, never as passed.

A check that reports a false failure is worse than no check: it teaches people to ignore the
whole verification pass.

The CLI exits non-zero if any check fails.

---

## Security posture

- Output directory `0700`, private keys `0600`, process `umask 077` — **on POSIX**. Windows
  gets an equivalent via `icacls`; see trap 4. Everything goes through `fsperm`, so the
  platform difference lives in one file rather than being scattered through `cli.py`
- **No extra plaintext intermediate files.** Decrypted data only ever exists in memory
- `--no-secrets` exports structure without passwords or passphrases
- **Orphaned keys are still written out** to `keys-unlinked/`, never silently dropped. Its
  `README.txt` states plainly that "not referenced" ≠ "not in use"
- The tool is **read-only**; it never modifies or deletes Termius data

`.gitignore` covers every output path. Note that its patterns are anchored — an unanchored
`localkey*` would also match `src/termius_export/localkey.py`, which is source code.

---

## Reverse-engineering method

The method matters more than the result. The cipher format was worked out like this:

**1. Find the key before attacking the ciphertext.**
The application has to store a decryption key somewhere. Desktop Electron apps almost always use
the OS keyring. Enumerate every entry and search on variations of the application name. Once you
have the key you have a way to verify hypotheses.

**2. Use known plaintext to measure the overhead.**
You don't know the algorithm, but you do know **what some plaintexts must be** — a host the user
never named has an empty-string label. The ciphertext length for empty plaintext *is* the
format's fixed overhead. Here: 42 bytes.

Cross-check with a variant: take the shortest address field and compute
`len(ciphertext) - len(plaintext)`. A constant result means a fixed-overhead AEAD rather than
block padding.

**3. Use the overhead number to guess the algorithm.**
42 = 2 + 24 + 16. A 24-byte nonce plus a 16-byte MAC is the signature of NaCl secretbox
(AES-GCM and ChaCha20-Poly1305-IETF are both 12 + 16). So what are the extra two bytes?

**4. Check whether the prefix is fixed or random.**
Collect the first N bytes of every ciphertext and deduplicate. All identical → a fixed header
(a version marker). All different → a random nonce. Here the first two bytes were always `0401`,
so: version header.

**5. Decrypt under the hypothesis, then validate across the whole corpus.**
Take the nonce from offset 2 and run secretbox. All 26 sampled fields decrypted, and all 9 private
keys came out containing `BEGIN ... PRIVATE KEY`. Hypothesis confirmed.

**Only a full-corpus pass counts as verification.** One or two successful fields can be luck.

A cautionary note: the first attempt read the nonce from offset 0, all 26 samples failed, and the
conclusion was nearly "this is a proprietary scheme, we must depend on the app's own native
module." **One failure is not enough to give up** — quantify the length relationships first, then
decide.

### Why Python, in the end

The original implementation was Node, because decryption had to call the application's bundled
native module via `ELECTRON_RUN_AS_NODE`. Once the cipher format was understood, that constraint
disappeared and the language was free again.

The single decisive reason for Python: **Chromium stores IndexedDB values in V8 structured-clone
format inside LevelDB, and `ccl_chromium_reader` already implements that.** Any other language
would require writing a V8 deserializer from scratch — the largest and most fragile part of the
whole project, and one that would keep breaking as Chromium evolves.

---

## Known limitations

- Fully verified on Linux (snap install). Windows support is implemented against a real
  install and its verification pass is still in progress — do not upgrade this line until a
  clean end-to-end run is confirmed. The macOS path/keyring branch follows platform
  conventions but has not been exercised on real hardware
- Hardware-backed keys (Apple Secure Enclave, Windows TPM) **cannot be exported** — the private
  key never leaves the hardware. Those must be regenerated
- The Tabby writer has not been round-trip verified; see the `verified` table above
- Only cipher version header `0401` has been observed. If upstream changes schemes the tool fails
  loudly rather than producing wrong output
