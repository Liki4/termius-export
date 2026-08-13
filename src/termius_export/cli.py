from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from . import fsperm
from . import writers as writers_mod
from .crypto import DecryptionFailed, Decryptor, UnknownCipherVersion, first_ciphertext
from .datadir import candidates as data_dir_candidates
from .datadir import default_data_dir
from .localkey import LocalKeyNotFound, load_local_key, wrong_key_message
from .model import Model
from .normalize import build_model
from .source import IndexedDbNotFound, locate_leveldb, read_tables
from .verify import verify_outputs
from .writers import WriteContext


def build_parser() -> argparse.ArgumentParser:
    writer_help = "\n".join(f"    {w.name:<10} {w.title}  [{w.verified}]" for w in writers_mod.WRITERS)
    return _add_arguments(
        argparse.ArgumentParser(
            prog="termius-export",
            description="Decrypt Termius's local data offline and convert it for other SSH clients.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"Output formats:\n{writer_help}\n\n"
            "verified: roundtrip = output was read back and validated by the target's own "
            "parser; upstream-source = fields follow the target client's source-code type "
            "definitions, without a round-trip import.",
        )
    )


def _add_arguments(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument(
        "--data-dir",
        default=None,
        help="Termius data directory (an IndexedDB or leveldb path also works). Auto-detected by default.",
    )
    p.add_argument("--out", default="out", help="output directory (default: out)")
    p.add_argument("--local-key-file", default=None, help="file holding localKey; defaults to the OS keyring")
    p.add_argument("--format", default="all", help="comma-separated output formats (default: all)")
    p.add_argument("--no-secrets", action="store_true", help="omit plaintext passwords and passphrases")
    p.add_argument("--no-keys", action="store_true", help="do not write private key files at all")
    p.add_argument("--no-verify", action="store_true", help="skip self-verification of the output")
    p.add_argument(
        "--keep-all-versions",
        action="store_true",
        help="keep historical record versions from LevelDB (debugging; produces duplicates)",
    )
    p.add_argument(
        "--http-proxy-as-socks5",
        action="store_true",
        help="emit HTTP proxies into SOCKS5-only targets (Termix). Only correct when the proxy "
        "is a mixed port that speaks both, e.g. Clash/mihomo/FlClash. Verify with: "
        "curl --socks5-hostname <host>:<port> https://example.com",
    )
    p.add_argument("--json", action="store_true", help="print a machine-readable summary only")
    return p


#: Moved to fsperm, which owns every platform-dependent filesystem concern: POSIX modes do not
#: exist on Windows and write_text translates newlines there. Aliased rather than renamed at
#: each call site to keep this change small.
_write_private = fsperm.write_private


def _dump_keys(model: Model, out_dir: pathlib.Path) -> dict[str, str]:
    """Write private keys to disk. Keys no host references are still written, never dropped."""
    paths: dict[str, str] = {}
    used: set[pathlib.Path] = set()
    for key in model.keys:
        target_dir = out_dir / ("keys" if key.linked else "keys-unlinked")
        candidate = target_dir / key.file_base
        n = 2
        while candidate in used:
            candidate = target_dir / f"{key.file_base}_{n}"
            n += 1
        used.add(candidate)
        _write_private(candidate, key.private_key, 0o600)
        if key.public_key:
            _write_private(candidate.with_suffix(candidate.suffix + ".pub"), key.public_key, 0o644)
        paths[key.id] = str(candidate.resolve())

    orphans = model.orphan_keys
    if orphans:
        _write_private(
            out_dir / "keys-unlinked" / "README.txt",
            "These private keys are not referenced by any host in the source data.\n"
            'Note: "not referenced" does NOT mean "not in use" - a key may well be used\n'
            "outside Termius. This tool never deletes anything; verify before you do.\n\n"
            + "\n".join(
                f"{k.label or '(no label)'}\t{k.file_base}\tpassphrase={'yes' if k.has_passphrase else 'no'}"
                for k in orphans
            )
            + "\n",
            0o600,
        )
    return paths


def _key_validator(tables):
    """A test for "does this key belong to this data", or None if it cannot be answered.

    Poly1305 gives a decisive answer, so which keyring entry to use is a question that can be
    tried rather than inferred. See ``localkey.find_local_key`` for why the fixed candidate
    order is not enough on its own.
    """
    sample = first_ciphertext(tables.tables)
    if sample is None:
        # Nothing encrypted to test against - an empty or fully plaintext profile. Rejecting
        # every candidate would be worse than useless, so fall back to first-one-wins: with no
        # ciphertext there is no wrong key.
        return None

    def works(candidate: str) -> bool:
        try:
            Decryptor.from_base64(candidate).field(sample)
        except (ValueError, DecryptionFailed, UnknownCipherVersion):
            return False
        return True

    return works


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.umask(0o077)

    data_dir = args.data_dir or default_data_dir()
    if not data_dir:
        print("Could not auto-detect the Termius data directory; pass --data-dir.", file=sys.stderr)
        print("Looked in:\n  " + "\n  ".join(data_dir_candidates()), file=sys.stderr)
        return 2

    try:
        leveldb = locate_leveldb(data_dir)
    except IndexedDbNotFound as exc:
        print(exc, file=sys.stderr)
        return 2

    # Read before choosing a key, not after. read_tables never needed one, and having the data
    # in hand turns key selection from a guess about install layout into a measurement.
    tables = read_tables(leveldb, keep_all_versions=args.keep_all_versions)

    try:
        key_b64, key_source = load_local_key(args.local_key_file, _key_validator(tables))
    except LocalKeyNotFound as exc:
        print(exc, file=sys.stderr)
        return 2

    dec = Decryptor.from_base64(key_b64)
    try:
        model = build_model(
            tables,
            dec,
            source_info={"leveldb": str(leveldb), "local_key_source": key_source},
        )
    except UnknownCipherVersion as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except DecryptionFailed as exc:
        # Reported separately from UnknownCipherVersion because the fix is different: an
        # unknown header means upstream changed schemes, a MAC failure means we hold the wrong
        # key and a different keyring entry will work. Without this the user got a traceback.
        print(f"error: {exc}", file=sys.stderr)
        print(wrong_key_message(key_source), file=sys.stderr)
        return 3

    out_dir = pathlib.Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    fsperm.secure_dir(out_dir)

    key_paths = {} if args.no_keys else _dump_keys(model, out_dir)
    ctx = WriteContext(
        include_secrets=not args.no_secrets,
        key_paths=key_paths,
        http_proxy_as_socks5=args.http_proxy_as_socks5,
    )

    written = []
    for writer in writers_mod.resolve([s.strip() for s in args.format.split(",") if s.strip()]):
        for f in writer.write(model, ctx):
            _write_private(out_dir / f.path, f.content, f.mode)
            written.append({"writer": writer.name, "file": f.path, "verified": writer.verified})

    checks = [] if args.no_verify else verify_outputs(out_dir, model)

    summary = {
        "out_dir": str(out_dir),
        "source": model.source,
        "stats": model.stats(),
        "written": written,
        "secrets_included": not args.no_secrets,
        "warnings": fsperm.warnings(),
        "verification": [
            {
                "check": c.name,
                "result": "skipped" if c.passed is None else ("pass" if c.passed else "FAIL"),
                "detail": c.detail,
            }
            for c in checks
        ],
    }

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        _print_human(summary)

    return 1 if any(c.passed is False for c in checks) else 0


def _print_human(s: dict) -> None:
    st = s["stats"]
    print(f"output:     {s['out_dir']}")
    print(f"source:     {s['source'].get('leveldb')}")
    print(f"key from:   {s['source'].get('local_key_source')}")
    print()
    print(
        f"{st['hosts']} hosts, {st['keys']} keys "
        f"({st['keys_linked']} linked / {st['keys_orphaned']} orphaned), "
        f"{st['forwards']} port forwards"
    )
    print(
        f"  key auth {st['hosts_with_key']}   with password {st['hosts_with_password']}"
        f"   via proxy {st['hosts_with_proxy']}   unnamed {st['hosts_without_label']}"
    )
    before = s["source"].get("rows_before_dedup") or {}
    if before:
        print("  raw rows before dedup: " + ", ".join(f"{k}={v}" for k, v in sorted(before.items())))
    print()
    print("files:")
    for w in s["written"]:
        print(f"  {w['file']:<24} [{w['verified']}]")
    if s.get("warnings"):
        print()
        print("warnings:")
        for w in s["warnings"]:
            print(f"  [WARN] {w}")
    if s["verification"]:
        print()
        print("verification:")
        for c in s["verification"]:
            mark = {"pass": "PASS", "FAIL": "FAIL", "skipped": "SKIP"}[c["result"]]
            print(f"  [{mark}] {c['check']}: {c['detail']}")
