"""Self-verification must not raise false alarms.

Both cases here were reported from a real 213-host export. Neither is a Windows problem and
neither was introduced by the Windows work - they are checker bugs that a large enough dataset
was always going to expose. A verification pass that cries wolf is worse than none, because it
trains people to ignore it.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "src")

from termius_export.model import Host, Model
from termius_export.verify import verify_openssh, verify_tabby
from termius_export.writers import WriteContext
from termius_export.writers.openssh import OpenSshWriter
from termius_export.writers.tabby import TabbyWriter


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.write_text(content, encoding="utf-8", newline="\n")
    return p


@unittest.skipUnless(shutil.which("ssh"), "ssh not installed")
class OpenSshReadbackTests(unittest.TestCase):
    """ssh -G canonicalises the hostname to lower case; the comparison must allow for it."""

    def _check(self, address):
        model = Model(hosts=[Host(id="h1", alias="demo", label="demo", address=address)])
        content = OpenSshWriter().write(model, WriteContext(include_secrets=True, key_paths={}))[0].content
        with tempfile.TemporaryDirectory() as tmp:
            return verify_openssh(_write(tmp, "sshconfig", content), model)

    def test_uppercase_hostname_is_not_reported_as_a_mismatch(self):
        # ssh -G turns "EXAMPLE-Web-Host4" into "example-web-host4"; DNS is case-insensitive.
        checks = self._check("EXAMPLE-Web-Host4")
        failed = [c for c in checks if c.passed is False]
        self.assertEqual(failed, [], f"false mismatch: {[c.detail for c in failed]}")

    def test_lowercase_hostname_still_passes(self):
        self.assertEqual([c for c in self._check("example.com") if c.passed is False], [])

    def test_a_genuine_mismatch_is_still_caught(self):
        model = Model(hosts=[Host(id="h1", alias="demo", label="demo", address="10.0.0.1")])
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "sshconfig", "Host demo\n    HostName 10.9.9.9\n")
            failed = [c for c in verify_openssh(path, model) if c.passed is False]
        self.assertTrue(failed, "a real hostname mismatch must still fail")


class TabbyQuoteTests(unittest.TestCase):
    """An escaped quote inside a value is valid, and must not be flagged."""

    def _verify(self, hosts):
        model = Model(hosts=hosts)
        content = TabbyWriter().write(model, WriteContext(include_secrets=True, key_paths={}))[0].content
        with tempfile.TemporaryDirectory() as tmp:
            return content, verify_tabby(_write(tmp, "tabby-profiles.yaml", content), model)

    def test_password_containing_a_double_quote_is_not_flagged(self):
        hosts = [Host(id="h1", alias="a", label="a", address="10.0.0.1", password='pa"ss')]
        content, checks = self._verify(hosts)
        self.assertIn(r"\"", content, "writer should JSON-escape the quote")
        failed = [c for c in checks if c.passed is False]
        self.assertEqual(failed, [], f"false alarm: {[c.detail for c in failed]}")

    def test_label_containing_a_double_quote_is_not_flagged(self):
        hosts = [Host(id="h1", alias="a", label='the "prod" box', address="10.0.0.1")]
        _, checks = self._verify(hosts)
        self.assertEqual([c for c in checks if c.passed is False], [])

    def test_backslash_and_non_ascii_are_not_flagged(self):
        hosts = [Host(id="h1", alias="a", label="生产\\服务器", address="10.0.0.1")]
        _, checks = self._verify(hosts)
        self.assertEqual([c for c in checks if c.passed is False], [])

    def test_genuinely_malformed_quoting_is_still_caught(self):
        model = Model(hosts=[Host(id="h1", alias="a", label="a", address="10.0.0.1")])
        broken = 'profiles:\n  - id: "ssh:custom:a:1"\n    name: "unterminated\n'
        with tempfile.TemporaryDirectory() as tmp:
            failed = [c for c in verify_tabby(_write(tmp, "t.yaml", broken), model) if c.passed is False]
        self.assertTrue(failed, "an unterminated quoted scalar must still fail")


if __name__ == "__main__":
    unittest.main()
