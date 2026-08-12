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

## Three traps

All three were hit during development. Don't rediscover them.

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

The CLI exits non-zero if any check fails.

---

## Security posture

- Output directory `0700`, private keys `0600`, process `umask 077`
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

- Fully verified only on Linux (snap install). The macOS and Windows path/keyring branches follow
  platform conventions but have not been exercised on real hardware
- Hardware-backed keys (Apple Secure Enclave, Windows TPM) **cannot be exported** — the private
  key never leaves the hardware. Those must be regenerated
- The Tabby writer has not been round-trip verified; see the `verified` table above
- Only cipher version header `0401` has been observed. If upstream changes schemes the tool fails
  loudly rather than producing wrong output
