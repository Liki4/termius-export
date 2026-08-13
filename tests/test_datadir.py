"""Data-directory auto-detection, including the macOS App Store container.

``cli`` cannot be imported from a test - it pulls PyNaCl and ccl_chromium_reader - which is why
``default_data_dir`` lives in its own stdlib-only module, the same way ``write_private`` lives
in ``fsperm``.

The bug being guarded against here is an inconsistency rather than a crash: ``localkey``
already knew App Store installs existed (``CANDIDATE_SERVICES`` carries ``"Termius (MAS)"``)
while the path list carried only the DMG location, so auto-detection could not have succeeded
on a Mac App Store install no matter what the keyring held.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "src")

from termius_export.datadir import (
    DEFAULT_DATA_DIR_GLOBS,
    DEFAULT_DATA_DIRS,
    candidates,
    default_data_dir,
)

MAS_CONTAINER = "Library/Containers/com.termius.mac/Data/Library/Application Support/Termius"
DMG_CONTAINER = "Library/Containers/com.termius-dmg.mac/Data/Library/Application Support/Termius"
DMG_PLAIN = "Library/Application Support/Termius"


def _home(path):
    """Point ``~`` at a temporary directory.

    ``expanduser`` reads HOME on POSIX and USERPROFILE on Windows, so both are set and the
    test runs unmodified on either platform.
    """
    return mock.patch.dict(os.environ, {"HOME": str(path), "USERPROFILE": str(path)})


class ContainerGlobTests(unittest.TestCase):
    def _with_dirs(self, *relative):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        made = []
        for rel in relative:
            p = Path(tmp.name) / rel
            p.mkdir(parents=True)
            made.append(p)
        return tmp.name, made

    def test_app_store_container_is_found(self):
        home, (target,) = self._with_dirs(MAS_CONTAINER)
        with _home(home):
            self.assertEqual(Path(default_data_dir()), target)

    def test_dmg_container_id_also_matches_the_glob(self):
        """The glob exists so the bundle id does not have to be guessed exactly."""
        home, (target,) = self._with_dirs(DMG_CONTAINER)
        with _home(home):
            self.assertEqual(Path(default_data_dir()), target)

    def test_the_plain_dmg_path_wins_over_a_leftover_container(self):
        """A machine that moved from the App Store build to the DMG build keeps the container.

        Measured on a real Mac: the App Store install left both a Group Container and a
        keychain entry behind when it was replaced. The live profile has to win, which is why
        the literals are tried before the globs.
        """
        home, (plain, _container) = self._with_dirs(DMG_PLAIN, MAS_CONTAINER)
        with _home(home):
            self.assertEqual(Path(default_data_dir()), plain)

    def test_an_unrelated_container_is_ignored(self):
        home, _ = self._with_dirs("Library/Containers/com.example.other/Data/Library/Application Support/Termius")
        with _home(home):
            self.assertIsNone(default_data_dir())

    def test_nothing_installed_returns_none(self):
        home, _ = self._with_dirs()
        with _home(home):
            self.assertIsNone(default_data_dir())

    def test_several_containers_resolve_deterministically(self):
        home, _ = self._with_dirs(MAS_CONTAINER, DMG_CONTAINER)
        with _home(home):
            first = default_data_dir()
            self.assertEqual(first, default_data_dir(), "must not depend on filesystem order")
        # sorted(): "com.termius-dmg.mac" < "com.termius.mac" because '-' precedes '.'.
        self.assertIn("com.termius-dmg.mac", first)


class CandidateListTests(unittest.TestCase):
    def test_candidates_reports_literals_first_then_globs(self):
        self.assertEqual(candidates()[: len(DEFAULT_DATA_DIRS)], DEFAULT_DATA_DIRS)
        self.assertEqual(candidates()[len(DEFAULT_DATA_DIRS) :], DEFAULT_DATA_DIR_GLOBS)

    def test_the_keyring_and_the_path_list_agree_that_app_store_installs_exist(self):
        """These two drifted apart once; keep them from drifting again."""
        from termius_export.localkey import CANDIDATE_SERVICES

        self.assertIn("Termius (MAS)", CANDIDATE_SERVICES)
        self.assertTrue(
            any("Containers" in c for c in candidates()),
            "localkey knows about sandboxed App Store installs, so the path list must too",
        )


if __name__ == "__main__":
    unittest.main()
