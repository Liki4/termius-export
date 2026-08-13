"""Where Termius keeps its data, per platform and per install type.

This lives outside ``cli`` on purpose. ``cli`` imports ``crypto`` and ``source``, which pull in
PyNaCl and ``ccl_chromium_reader``, so a test that imported it would fail on a bare checkout —
the same reason ``write_private`` lives in ``fsperm``. Everything here is stdlib-only.

The macOS App Store build is the awkward case, and the code used to be internally inconsistent
about whether it existed at all: ``localkey.CANDIDATE_SERVICES`` carried ``"Termius (MAS)"``
while the path list carried only the DMG location, so auto-detection could not have worked on
a Mac App Store install.

App Store builds are sandboxed, so Electron resolves ``userData`` **inside the app container**
rather than under ``~/Library/Application Support``, and the container is named after the
bundle id. The id is globbed rather than hard-coded, because it is Termius's to change and
because the two known ids differ by just enough to make a literal for one silently miss the
other: measured on a real Mac, the DMG build is ``com.termius-dmg.mac`` and the App Store build
is ``com.termius.mac``.
"""

from __future__ import annotations

import glob
import os
import pathlib

#: Literal locations, tried in order; first existing directory wins.
DEFAULT_DATA_DIRS = [
    "~/snap/termius-app/current/.config/Termius",
    "~/.config/Termius",
    "~/Library/Application Support/Termius",
    "~/AppData/Roaming/Termius",
]

#: Tried only after every literal, for install types whose path embeds a bundle id.
#: Deliberately last: the DMG location above is the one verified on real hardware, so a machine
#: carrying leftovers from a previous App Store install still resolves to its live profile.
DEFAULT_DATA_DIR_GLOBS = [
    "~/Library/Containers/*ermius*/Data/Library/Application Support/Termius",
]


def candidates() -> list[str]:
    """Every location that will be tried, in order, for the "not found" message."""
    return [*DEFAULT_DATA_DIRS, *DEFAULT_DATA_DIR_GLOBS]


def default_data_dir() -> str | None:
    """The first Termius data directory that exists, or None."""
    for candidate in DEFAULT_DATA_DIRS:
        p = pathlib.Path(candidate).expanduser()
        if p.is_dir():
            return str(p)

    for pattern in DEFAULT_DATA_DIR_GLOBS:
        # sorted() so that a machine with more than one matching container resolves the same
        # way on every run, rather than following whatever order the filesystem returns.
        for match in sorted(glob.glob(os.path.expanduser(pattern))):
            if os.path.isdir(match):
                return match

    return None
