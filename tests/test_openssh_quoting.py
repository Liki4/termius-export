"""IdentityFile quoting.

The critical assertion is the negative one: paths without whitespace must come out
byte-identical, because openssh.py is shared code rather than a platform branch and Linux
output must not change.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.writers.openssh import _quote_path


class QuotePathTests(unittest.TestCase):
    def test_path_without_spaces_is_returned_unchanged(self):
        path = "/home/alice/out/keys/id_ed25519"
        self.assertEqual(_quote_path(path), path)

    def test_windows_path_without_spaces_is_returned_unchanged(self):
        path = r"C:\Users\Alice\out\keys\id_ed25519"
        self.assertEqual(_quote_path(path), path)

    def test_path_with_space_is_quoted(self):
        self.assertEqual(
            _quote_path(r"C:\Users\First Last\out\keys\id_ed25519"),
            r'"C:\Users\First Last\out\keys\id_ed25519"',
        )

    def test_path_with_tab_is_quoted(self):
        self.assertEqual(_quote_path("/tmp/a\tb/key"), '"/tmp/a\tb/key"')

    def test_empty_path_is_returned_unchanged(self):
        self.assertEqual(_quote_path(""), "")


import shutil
import subprocess
import tempfile
from pathlib import Path

from termius_export.model import Host, Key, Model
from termius_export.writers import WriteContext
from termius_export.writers.openssh import OpenSshWriter


def _ssh_G(config_path, alias):
    out = subprocess.run(
        ["ssh", "-G", "-F", str(config_path), alias],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    values = {}
    for line in out.splitlines():
        head, _, tail = line.partition(" ")
        values.setdefault(head, tail.strip())
    return values


@unittest.skipUnless(shutil.which("ssh"), "ssh not installed")
class SshAcceptsQuotedIdentityFileTests(unittest.TestCase):
    def _render(self, key_path):
        key = Key(id="k1", label="test", file_base="id_ed25519", private_key="x")
        model = Model(
            hosts=[
                Host(
                    id="h1",
                    alias="demo",
                    label="demo",
                    address="10.0.0.1",
                    port=2222,
                    username="alice",
                    key=key,
                )
            ]
        )
        ctx = WriteContext(include_secrets=True, key_paths={"k1": key_path})
        return OpenSshWriter().write(model, ctx)[0].content

    def _resolve(self, key_path):
        content = self._render(key_path)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "sshconfig"
            cfg.write_text(content, encoding="utf-8", newline="\n")
            return _ssh_G(cfg, "demo"), content

    def test_ssh_resolves_host_with_spaced_key_path(self):
        values, content = self._resolve("/tmp/First Last/id_ed25519")
        self.assertIn('IdentityFile "/tmp/First Last/id_ed25519"', content)
        self.assertEqual(values["hostname"], "10.0.0.1")
        self.assertEqual(values["port"], "2222")
        self.assertEqual(values["user"], "alice")

    def test_ssh_resolves_host_with_plain_key_path(self):
        values, content = self._resolve("/tmp/plain/id_ed25519")
        self.assertIn("IdentityFile /tmp/plain/id_ed25519", content)
        self.assertNotIn('"', content)
        self.assertEqual(values["hostname"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
