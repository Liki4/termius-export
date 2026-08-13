"""Self-verification must not raise false alarms, and must name the right cause when it does.

The first two cases were reported from a real 213-host export. Neither is a Windows problem and
neither was introduced by the Windows work - they are checker bugs that a large enough dataset
was always going to expose. A verification pass that cries wolf is worse than none, because it
trains people to ignore it.

The third came from the first real macOS run. It is the opposite failure: the check was right
to fail, but it blamed the wrong thing. ssh had refused to run at all, and the report said the
resolved hostname disagreed - which sends the reader looking for a wrong address instead of an
unusable alias. A check that misnames the cause costs almost as much as one that cries wolf.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "src")

from termius_export import verify as verify_module
from termius_export.model import Host, Model
from termius_export.verify import verify_openssh, verify_tabby
from termius_export.writers import WriteContext
from termius_export.writers.openssh import OpenSshWriter
from termius_export.writers.tabby import TabbyWriter


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.write_text(content, encoding="utf-8", newline="\n")
    return p


def refusing_run(destinations):
    """Wrap ``verify._run`` so that the named destinations come back refused.

    **There is no destination every ssh refuses.** The first attempt at these tests used a
    space, on the reasoning that no ctype table anywhere calls it alphanumeric — and CI showed
    Win32 OpenSSH accepting both a space and a leading dash where macOS refuses both. Which
    inputs get refused is a property of the platform, not something a test can pin down.

    So only the refusal itself is simulated. Everything else still goes to the real ssh: the
    config is parsed by ssh, and accepted aliases are resolved by ssh. What is under test here
    is how ``verify_openssh`` *reports* a refusal, which is our code and should not vary by
    platform.
    """
    real = verify_module._run

    def run(args, **kwargs):
        if args[-1] in destinations:
            return subprocess.CompletedProcess(
                args, returncode=255, stdout="", stderr="hostname contains invalid characters\n"
            )
        return real(args, **kwargs)

    return mock.patch.object(verify_module, "_run", run)


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


@unittest.skipUnless(shutil.which("ssh"), "ssh not installed")
class OpenSshAliasRejectionTests(unittest.TestCase):
    """An alias ssh refuses is a different defect from a value ssh disagrees with.

    Only the refusal is simulated, via ``refusing_run``; the config is still parsed by a real
    ssh and accepted aliases are still resolved by it. See that helper for why no real input
    works here: which destinations ssh refuses varies by platform, so a test that needs one
    cannot get it portably.
    """

    def _by_name(self, config, model, refuse=()):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "sshconfig", config)
            with refusing_run(set(refuse)):
                return {c.name: c for c in verify_openssh(path, model)}

    def test_a_rejected_alias_is_not_reported_as_a_hostname_mismatch(self):
        model = Model(hosts=[Host(id="h1", alias="demo", label="x", address="10.0.0.1")])
        checks = self._by_name("Host demo\n    HostName 10.0.0.1\n", model, refuse=["demo"])

        alias_check = checks["openssh: alias accepted by ssh"]
        self.assertIs(alias_check.passed, False)
        self.assertIn("demo", alias_check.detail)
        # ssh's own reason is carried through, in parentheses after the alias.
        self.assertIn("(", alias_check.detail)

        self.assertNotIn("hostname", checks["openssh: per-host readback"].detail)

    def test_an_accepted_alias_passes_both_checks(self):
        model = Model(hosts=[Host(id="h1", alias="demo", label="demo", address="10.0.0.1")])
        checks = self._by_name("Host demo\n    HostName 10.0.0.1\n", model)
        self.assertIs(checks["openssh: alias accepted by ssh"].passed, True)
        self.assertIs(checks["openssh: per-host readback"].passed, True)

    def test_a_rejected_alias_does_not_mask_a_real_mismatch(self):
        model = Model(
            hosts=[
                Host(id="h1", alias="refused", label="x", address="10.0.0.1"),
                Host(id="h2", alias="demo", label="demo", address="10.0.0.2"),
            ]
        )
        config = "Host refused\n    HostName 10.0.0.1\n\nHost demo\n    HostName 10.9.9.9\n"
        checks = self._by_name(config, model, refuse=["refused"])
        self.assertIs(checks["openssh: alias accepted by ssh"].passed, False)
        self.assertIs(checks["openssh: per-host readback"].passed, False)
        self.assertIn("demo: hostname", checks["openssh: per-host readback"].detail)

    def test_a_rejected_first_alias_does_not_abort_the_whole_verification(self):
        """The parse probe must not use a host alias.

        Hosts are sorted by alias, so a profile whose aliases are all non-ASCII puts a
        rejected one first. Probing with it reported a perfectly good config as "ssh rejected
        the config" and suppressed every check after it.
        """
        model = Model(hosts=[Host(id="h1", alias="refused", label="x", address="10.0.0.1")])
        checks = self._by_name("Host refused\n    HostName 10.0.0.1\n", model, refuse=["refused"])
        self.assertIs(checks["openssh: ssh -G parse"].passed, True)
        self.assertIn("openssh: per-host readback", checks, "later checks must still run")

    def test_a_genuinely_broken_config_is_still_caught(self):
        model = Model(hosts=[Host(id="h1", alias="demo", label="demo", address="10.0.0.1")])
        # An unquoted IdentityFile path with a space: ssh rejects the whole file.
        broken = "Host demo\n    HostName 10.0.0.1\n    IdentityFile /tmp/a b/id_rsa\n"
        checks = self._by_name(broken, model)
        self.assertIs(checks["openssh: ssh -G parse"].passed, False)


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
