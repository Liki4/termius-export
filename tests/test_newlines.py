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
