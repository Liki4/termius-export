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


if __name__ == "__main__":
    unittest.main()
