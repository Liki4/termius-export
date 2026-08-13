"""Where an exported private key lands on disk, and under what name.

This logic used to live in `cli._dump_keys`, where the suite could not reach it - CLAUDE.md
forbids importing `cli` from a test, because `cli` pulls PyNaCl and ccl_chromium_reader and the
suite has to run from a bare checkout. That is the same reason `write_private` moved to
`fsperm` and `first_ciphertext` moved to `envelope`, and it hid two real defects here.

Both were silent. Neither raises, neither is caught by `verify_key_files` - which skips `*.pub`
by suffix, so the very file the collision corrupts is the one it does not look at - and neither
shows up in the summary. An export can therefore be missing a private key entirely and report
every check green.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, "src")

from termius_export.keyfiles import dump_keys
from termius_export.model import Key, Model
from termius_export.normalize import build_model
from termius_export.verify import verify_key_files


def _key(id, file_base, private, public="", linked=True):
    return Key(
        id=id,
        label=file_base,
        file_base=file_base,
        private_key=private,
        public_key=public,
        linked=linked,
    )


class DumpKeysTests(unittest.TestCase):
    def setUp(self):
        self.out = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(_rmtree, self.out)

    def _dump(self, *keys):
        paths = dump_keys(Model(keys=list(keys)), self.out)
        return paths, {p.name: p.read_text() for p in sorted(self.out.rglob("*")) if p.is_file()}

    def test_a_public_key_cannot_overwrite_another_keys_private_key(self):
        """The defect, in the ordering that loses a private key outright.

        `id_rsa.pub` is a name `slug` produces from a label of that name - dots survive it. The
        old allocator registered only private-key paths, so writing `id_rsa`'s derived public
        key landed on top of the private key already written for the key *called* `id_rsa.pub`.
        """
        paths, files = self._dump(
            _key("B", "id_rsa.pub", "PRIVATE-B\n"),
            _key("A", "id_rsa", "PRIVATE-A\n", public="PUBLIC-A\n"),
        )
        self.assertEqual(pathlib.Path(paths["B"]).read_text(), "PRIVATE-B\n")
        self.assertEqual(pathlib.Path(paths["A"]).read_text(), "PRIVATE-A\n")
        self.assertIn("PUBLIC-A\n", files.values())

    def test_a_private_key_cannot_overwrite_another_keys_public_key(self):
        """The other ordering. Less costly, but it leaves a private key in a file named .pub -
        which `verify_key_files` skips by suffix, so it is never even fingerprint-checked."""
        paths, files = self._dump(
            _key("A", "id_rsa", "PRIVATE-A\n", public="PUBLIC-A\n"),
            _key("B", "id_rsa.pub", "PRIVATE-B\n"),
        )
        self.assertEqual(pathlib.Path(paths["A"]).read_text(), "PRIVATE-A\n")
        self.assertEqual(pathlib.Path(paths["B"]).read_text(), "PRIVATE-B\n")
        self.assertIn("PUBLIC-A\n", files.values())

    def test_no_private_key_is_written_to_a_pub_path(self):
        """The invariant behind both cases: `.pub` means public, everywhere, always.

        `verify_key_files` relies on it to decide what to fingerprint, so a private key hiding
        under that suffix is unverified as well as misnamed.
        """
        paths, _ = self._dump(
            _key("A", "id_rsa", "PRIVATE-A\n", public="PUBLIC-A\n"),
            _key("B", "id_rsa.pub", "PRIVATE-B\n"),
        )
        for key_id, path in paths.items():
            self.assertFalse(pathlib.Path(path).name.endswith(".pub"), f"{key_id} -> {path}")

    def test_two_keys_with_the_same_name_still_get_distinct_files(self):
        """Pre-existing behaviour, pinned so the fix does not regress it."""
        paths, _ = self._dump(
            _key("A", "id_rsa", "PRIVATE-A\n"),
            _key("B", "id_rsa", "PRIVATE-B\n"),
        )
        self.assertNotEqual(paths["A"], paths["B"])
        self.assertEqual(pathlib.Path(paths["A"]).read_text(), "PRIVATE-A\n")
        self.assertEqual(pathlib.Path(paths["B"]).read_text(), "PRIVATE-B\n")

    def test_a_public_key_is_written_beside_its_private_key(self):
        paths, files = self._dump(_key("A", "id_rsa", "PRIVATE-A\n", public="PUBLIC-A\n"))
        self.assertEqual(pathlib.Path(paths["A"]).name, "id_rsa")
        self.assertEqual(files["id_rsa.pub"], "PUBLIC-A\n")

    def test_unlinked_keys_go_to_their_own_directory_with_a_readme(self):
        """Orphans are never dropped, and the README says what "orphan" does not mean."""
        paths, files = self._dump(_key("A", "spare", "PRIVATE-A\n", linked=False))
        self.assertEqual(pathlib.Path(paths["A"]).parent.name, "keys-unlinked")
        self.assertIn("README.txt", files)
        self.assertIn("not referenced", files["README.txt"])

    def test_a_linked_and_an_unlinked_key_may_share_a_name(self):
        """Different directories, so there is no collision to resolve."""
        paths, _ = self._dump(
            _key("A", "id_rsa", "PRIVATE-A\n", linked=True),
            _key("B", "id_rsa", "PRIVATE-B\n", linked=False),
        )
        self.assertEqual(pathlib.Path(paths["A"]).name, "id_rsa")
        self.assertEqual(pathlib.Path(paths["B"]).name, "id_rsa")


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class DumpedKeysAreActuallyVerifiedTests(unittest.TestCase):
    """The half that made the collision invisible: what `verify_key_files` ends up checking.

    It decides by suffix, skipping `*.pub` and `*.txt`. So a key named `id_rsa.pub` was not
    merely corrupted by the collision - it was excluded from the fingerprint check as well, and
    a key named `notes.txt` was excluded with no collision at all. Both were exported and both
    reported green. This closes the loop with real keys and OpenSSH's own parser.
    """

    def _real_key(self, id, file_base, tmp):
        target = pathlib.Path(tmp) / id
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(target), "-q"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return _key(id, file_base, target.read_text(), public=target.with_suffix(".pub").read_text())

    def test_a_key_named_like_a_public_key_is_still_fingerprinted(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            model = Model(
                keys=[
                    self._real_key("A", "id_rsa", src),
                    self._real_key("B", "id_rsa.pub", src),
                    self._real_key("C", "notes.txt", src),
                ]
            )
            out_dir = pathlib.Path(out)
            dump_keys(model, out_dir)
            checks = {c.name: c for c in verify_key_files(out_dir, model)}

        parse = checks["keys: ssh-keygen parse"]
        self.assertIs(parse.passed, True, parse.detail)
        self.assertIn("all 3", parse.detail, "every exported private key must reach the check")


class _Tables:
    def __init__(self, tables):
        self.tables = tables
        self.counts_before_dedup = {name: len(rows) for name, rows in tables.items()}


class _NoopDecryptor:
    """Stands in for crypto.Decryptor, which the suite must not import."""

    stats = {"decrypted": 0, "plain": 0, "failed": 0}

    def walk(self, node):
        return node


class KeyFileBaseTests(unittest.TestCase):
    """`file_base` is a filename, so it has to be built with the filename rule, not the ssh one."""

    def _keys(self, *labels):
        rows = [
            {"id": str(i), "local_id": str(i), "label": label, "private_key": "PRIVATE\n"}
            for i, label in enumerate(labels)
        ]
        return build_model(_Tables({"keys": rows}), _NoopDecryptor()).keys

    def test_a_label_that_is_only_dots_does_not_become_a_path_component(self):
        for label in (".", ".."):
            (key,) = self._keys(label)
            self.assertNotIn(key.file_base, (".", ".."), label)

    def test_a_windows_device_name_does_not_survive_into_a_filename(self):
        (key,) = self._keys("NUL")
        self.assertNotEqual(key.file_base.upper(), "NUL")

    def test_an_ordinary_label_is_still_used_verbatim(self):
        (key,) = self._keys("deploy-key")
        self.assertEqual(key.file_base, "deploy-key")


def _rmtree(path):
    import shutil

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
