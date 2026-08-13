"""A passphrase-protected PKCS#1 PEM key is not a corrupt key.

Reported from a real export: one key came back as "unparseable". It was not. Old PEM keys
encrypt the whole body, public modulus included, so ssh-keygen cannot fingerprint one without
its passphrase and says "<file> is not a key file" - by exit status, indistinguishable from
genuine corruption. The modern OPENSSH format keeps the public half in the clear, which is why
only old keys hit this.

Reporting that as a failure is wrong, but so is reporting it as a pass: it genuinely was not
verified. It gets its own skipped check saying exactly what was not checked and why.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "src")

from termius_export.model import Key, Model
from termius_export.verify import _is_encrypted_pem, verify_key_files

ENCRYPTED_PEM = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF

bm90IHJlYWxseSBlbmNyeXB0ZWQgYnV0IHNoYXBlZCBsaWtlIGl0
-----END RSA PRIVATE KEY-----
"""


def _keys_dir():
    tmp = tempfile.mkdtemp()
    d = Path(tmp) / "keys"
    d.mkdir(parents=True)
    return d


def _model(n):
    keys = [Key(id=f"k{i}", label=f"k{i}", file_base=f"k{i}", private_key="x") for i in range(n)]
    return Model(keys=keys)


class IsEncryptedPemTests(unittest.TestCase):
    def test_detects_the_pem_encryption_marker(self):
        d = _keys_dir()
        p = d / "old"
        p.write_text(ENCRYPTED_PEM, encoding="utf-8", newline="\n")
        self.assertTrue(_is_encrypted_pem(p))

    def test_plain_pem_is_not_flagged(self):
        d = _keys_dir()
        p = d / "plain"
        p.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8", newline="\n"
        )
        self.assertFalse(_is_encrypted_pem(p))

    def test_openssh_format_is_not_flagged(self):
        d = _keys_dir()
        p = d / "modern"
        p.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            encoding="utf-8",
            newline="\n",
        )
        self.assertFalse(_is_encrypted_pem(p))


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class VerifyKeyFilesTests(unittest.TestCase):
    def test_encrypted_pem_is_skipped_not_failed(self):
        d = _keys_dir()
        (d / "legacy-rsa-key").write_text(ENCRYPTED_PEM, encoding="utf-8", newline="\n")
        checks = verify_key_files(d.parent, _model(1))
        self.assertEqual([c for c in checks if c.passed is False], [], "must not be a failure")
        skipped = [c for c in checks if c.passed is None]
        self.assertTrue(skipped, "must be reported as skipped, not silently passed")
        self.assertIn("legacy-rsa-key", " ".join(c.detail for c in skipped))

    def test_a_genuinely_corrupt_key_still_fails(self):
        d = _keys_dir()
        (d / "broken").write_text("this is not a key at all\n", encoding="utf-8", newline="\n")
        checks = verify_key_files(d.parent, _model(1))
        failed = [c for c in checks if c.passed is False]
        self.assertTrue(failed, "corruption must still be caught")
        self.assertIn("broken", failed[0].detail)

    def test_a_real_key_still_passes(self):
        d = _keys_dir()
        target = d / "good"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(target), "-q"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        (d / "good.pub").unlink()  # force ssh-keygen to read the private key itself
        checks = verify_key_files(d.parent, _model(1))
        self.assertEqual([c for c in checks if c.passed is False], [])
        self.assertTrue([c for c in checks if c.passed is True])

    def test_mixed_set_is_partitioned_correctly(self):
        d = _keys_dir()
        (d / "locked").write_text(ENCRYPTED_PEM, encoding="utf-8", newline="\n")
        (d / "broken").write_text("garbage\n", encoding="utf-8", newline="\n")
        target = d / "good"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(target), "-q"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        (d / "good.pub").unlink()
        checks = verify_key_files(d.parent, _model(3))
        failed = [c for c in checks if c.passed is False]
        skipped = [c for c in checks if c.passed is None]
        self.assertTrue(failed, "the corrupt key must be reported")
        self.assertIn("broken", failed[0].detail)
        self.assertNotIn("locked", failed[0].detail, "the encrypted key is not corrupt")
        self.assertIn("locked", " ".join(c.detail for c in skipped))


if __name__ == "__main__":
    unittest.main()
