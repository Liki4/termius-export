# termius-export

Decrypt Termius's local data offline and convert your hosts, SSH keys, port forwards and proxy
settings into configuration for other SSH clients.

**Termius does not need to be running.** No debug port, no launching the app — the tool reads the
IndexedDB directly off disk, so it works on a cold backup directory too.

> Not affiliated with, endorsed by, or supported by Termius. "Termius" is used here only to
> identify the application whose data format this tool reads.

## Why this exists

Termius's own "Export" pushes your **public key to a server**. It is not a way to get your data
out as files. There is no official path for moving your hosts and keys to another client.

## Output formats

| Format | File | Verification |
|---|---|---|
| OpenSSH client config | `sshconfig` | `roundtrip` |
| Normalized JSON model | `export.json` | `roundtrip` |
| Generic CSV (Termius import template columns) | `hosts.csv` | `roundtrip` |
| Tabby profiles | `tabby-profiles.yaml` | `upstream-source` |
| Termix bulk-import payload | `termix-hosts.json` | `roundtrip` |
| OpenSSH known_hosts | `known_hosts` | `roundtrip` |

Note that Termix *can* import an SSH config, but its parser only reads Host / HostName /
User / Port / IdentityFile / ProxyJump — proxies, port forwards and all credentials are
dropped. Use `termix-hosts.json` instead; it carries them.

Private keys are written to `keys/`. Keys **not referenced by any host are not discarded** — they
go to `keys-unlinked/` with a note explaining that "not referenced" is not the same as "not in
use".

`roundtrip` means the output was read back and validated by the target's own parser.
`upstream-source` means fields follow the target client's type definitions in its source code, but
no import round-trip was performed. Writers based purely on guesswork are not shipped — see
[CLAUDE.md](CLAUDE.md).

## Usage

```bash
nix develop                          # or: pip install -e .
python -m termius_export --out out
```

Auto-detects the data directory, reads the decryption key from the OS keyring, emits every format
and self-verifies.

**On macOS, expect a keychain prompt.** The key was written by Termius, so reading it from
anything else raises the system's Allow / Always Allow / Deny dialog, once per keychain entry.
The export waits for it. Choosing *Always Allow* grants the trust to `/usr/bin/security` — that
is, to anything on the machine that shells out to it — and is revocable in Keychain Access under
the entry's **Access Control** tab.

```bash
# only some formats, and no plaintext passwords
python -m termius_export --format openssh,tabby --no-secrets

# work from a backup
python -m termius_export --data-dir ~/termius-backup/Termius --out out
```

See `--help` for all options.

### If the key cannot be read automatically

The decryption key (`localKey`) normally comes from the OS keyring. Two things can go wrong,
and they need different fixes — the tool tells you which one you hit.

**No keyring client installed.** On Linux the key is read via `secret-tool` from
`libsecret`. If it is missing, install it:

```bash
sudo dnf install libsecret          # Fedora / RHEL
sudo apt install libsecret-tools    # Debian / Ubuntu
sudo pacman -S libsecret            # Arch
nix shell nixpkgs#libsecret         # nix, no install needed
```

**Or bypass the keyring entirely.** Read the key yourself and pass it in:

```bash
# Linux
secret-tool lookup service termius-app account localKey > localkey.txt
# macOS
security find-generic-password -s Termius -a localKey -w > localkey.txt

chmod 600 localkey.txt
python -m termius_export --local-key-file localkey.txt --out out
```

The service name is `termius-app` for snap installs and `Termius` on macOS — Termius uses its
executable name, which is why looking up "Termius" on a snap install finds nothing. Any keyring
browser (Seahorse, KWalletManager) can show the entry too.

**A third case, if the export stops with "it does not decrypt this data".** A key was found, but
the wrong one. Moving between the macOS App Store and DMG builds leaves the old keychain entry
behind, and the two hold different keys. List what you actually have, then pass the right one in
with `--local-key-file`:

```bash
security dump-keychain | grep -i termius            # macOS
secret-tool search --all service termius-app        # Linux
```

On Windows the key lives in Credential Manager under the target `Termius/localKey`. The tool
reads it directly via `CredReadW`; to confirm the entry exists:

```powershell
cmdkey /list | Select-String termius
```

`cmdkey` lists targets but never prints the blob, so there is no one-line way to dump the key
by hand. If the automatic read fails, report the target name it shows.

`localkey.txt` is the master decryption key. Delete it once the export is done.

## After the export

The generated `sshconfig` points `IdentityFile` at this export's `keys/` directory. Two ways to
adopt it:

**Keep it separate and include it.** Least invasive — your existing config is untouched:

```bash
OUT=$(pwd)/out                      # wherever you pointed --out

mkdir -p ~/.ssh/config.d
cp "$OUT/sshconfig" ~/.ssh/config.d/termius
cp -r "$OUT/keys" ~/.ssh/termius-keys && chmod 700 ~/.ssh/termius-keys

# repoint IdentityFile at the new key location
sed -i "s|$OUT/keys/|$HOME/.ssh/termius-keys/|g" ~/.ssh/config.d/termius

# Include must come BEFORE any Host block, so prepend it
printf 'Include config.d/*\n' | cat - ~/.ssh/config > ~/.ssh/config.tmp \
  && mv ~/.ssh/config.tmp ~/.ssh/config
```

Relative `Include` paths resolve against `~/.ssh/`, which is why `config.d/*` works.

**Or merge it in.** Append `out/sshconfig` to `~/.ssh/config` and fix the `IdentityFile` paths
the same way.

Then verify a host resolves as expected before trusting the rest:

```bash
ssh -G <alias> | head -5
ssh <alias>
```

Other outputs:

- `known_hosts` — merge into `~/.ssh/known_hosts`, or use with `-o UserKnownHostsFile=`
- `hosts.csv` — import into Termius or another manager
- `tabby-profiles.yaml` — merge into the `profiles` list in `~/.config/tabby/config.yaml`
- `termix-hosts.json` — import from the Termix Hosts panel
- `keys-unlinked/` — private keys no host referenced; read its `README.txt` before deleting any

## Security

- Output directory `0700`, private keys `0600`, process `umask 077`
- On Windows POSIX modes do not apply: `os.chmod` there can only toggle the read-only
  attribute, so a `0600` private key would be protected by nothing. The output directory is
  restricted with `icacls` to the current user's SID and files inherit it. If that fails the
  run warns rather than letting you assume the keys are protected
- Decrypted data exists only in memory; no extra plaintext intermediate files are written
- The tool is **read-only** and never modifies or deletes Termius data
- Output contains plaintext credentials. `.gitignore` covers every output path, but handle the
  directory accordingly

## Limitations

- Verified on Linux (snap install), on Windows, and on macOS (DMG build). Both the Windows and
  macOS runs were real 213-host, 22-key profiles: the key read from the platform credential
  store, the data directory auto-detected, all six formats emitted and self-checked. The macOS
  **App Store** build has not been exercised — it is sandboxed, so its data lives in an app
  container; the container is globbed rather than hard-coded, but the path is inferred
- Whether `ssh` accepts a non-ASCII alias depends on the C library, not on OpenSSH: glibc takes
  one under any locale, macOS refuses one under any UTF-8 locale. Since a generated `sshconfig`
  is meant to be portable, hosts whose name is not ASCII get a **second `Host` pattern** that
  works everywhere — `Host 生产服务器 host-1`. The original is kept and listed first, so nothing
  changes for anyone whose names were already ASCII
- Hardware-backed keys (Apple Secure Enclave, Windows TPM) **cannot be exported** — the private
  key never leaves the hardware and must be regenerated
- Passphrase-protected **PKCS#1 PEM** keys (`BEGIN RSA PRIVATE KEY` with `Proc-Type:
  4,ENCRYPTED`) are exported normally but **cannot be self-verified**: that format encrypts the
  public modulus too, so `ssh-keygen` cannot fingerprint them without the passphrase. They are
  reported as skipped, never as passed. Keys in the modern OpenSSH format are unaffected

## Documentation

Implementation details, the reverse-engineering write-up, the traps to avoid, and how to add a new
writer are all in [CLAUDE.md](CLAUDE.md).

## Prior art

[ZeroP27/termius-local-export](https://github.com/ZeroP27/termius-local-export) — a Node tool
that decrypts Termius data by delegating to the application's own bundled native module. This
project started from it and then diverged completely: once the cipher format was
reverse-engineered there was no need to run Termius at all, which allowed the direct-LevelDB
read and the rewrite in Python. No code is shared.

## License

MIT — see [LICENSE](LICENSE).
