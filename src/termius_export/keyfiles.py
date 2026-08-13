"""Writing exported private keys to disk: which directory, under what name.

Moved out of ``cli`` so the suite can reach it. ``cli`` imports PyNaCl and
``ccl_chromium_reader``, which puts everything in it beyond the reach of a bare checkout - the
same reason ``write_private`` lives in ``fsperm`` and ``first_ciphertext`` in ``envelope``.
This module imports neither.
"""

from __future__ import annotations

import pathlib

from . import fsperm
from .model import Model

#: Suffixes ``verify.verify_key_files`` uses to decide a file is *not* a private key, so that
#: it skips the ``.pub`` siblings and the orphan README this module writes. That makes the
#: suffix a contract rather than a formatting detail: a private key landing on one is excluded
#: from the fingerprint check, silently, and a check that quietly stops checking is exactly
#: what this project rates as worse than no check at all.
_NOT_A_PRIVATE_KEY = (".pub", ".txt")


def _public_path(private: pathlib.Path) -> pathlib.Path:
    """The path the public half of ``private`` is written to."""
    return private.with_suffix(private.suffix + ".pub")


def _allocate(target_dir: pathlib.Path, file_base: str, used: set[pathlib.Path]) -> pathlib.Path:
    """Reserve a private-key path, and the ``.pub`` path derived from it, together.

    Reserving them as a pair is the whole point. Registering only the private path let a
    derived ``.pub`` write land on a private key already written for a key *named* ``x.pub`` -
    dots survive ``slug``, so that is an ordinary label - destroying it with no error. The
    public path is reserved even when this key has no public half, so the rule holds regardless
    of which keys happen to carry one.

    A name that would end in a suffix the verifier reads as "not a private key" is treated as
    taken, for the same reason: the counter suffix moves it out of the way (``id_rsa.pub`` ->
    ``id_rsa.pub_2``), so no private key can hide behind one.
    """
    n = 1
    while True:
        candidate = target_dir / (file_base if n == 1 else f"{file_base}_{n}")
        public = _public_path(candidate)
        if candidate not in used and public not in used and not candidate.name.endswith(_NOT_A_PRIVATE_KEY):
            used.add(candidate)
            used.add(public)
            return candidate
        n += 1


def dump_keys(model: Model, out_dir: pathlib.Path) -> dict[str, str]:
    """Write private keys to disk. Keys no host references are still written, never dropped."""
    paths: dict[str, str] = {}
    used: set[pathlib.Path] = set()
    for key in model.keys:
        target_dir = out_dir / ("keys" if key.linked else "keys-unlinked")
        candidate = _allocate(target_dir, key.file_base, used)
        fsperm.write_private(candidate, key.private_key, 0o600)
        if key.public_key:
            fsperm.write_private(_public_path(candidate), key.public_key, 0o644)
        paths[key.id] = str(candidate.resolve())

    orphans = model.orphan_keys
    if orphans:
        fsperm.write_private(
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
