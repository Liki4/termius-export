"""The second, ASCII-only `Host` pattern.

Whether ssh accepts a non-ASCII destination depends on the **C library**, not on OpenSSH:
glibc accepts CJK under every locale, macOS rejects it under any UTF-8 one. A generated
sshconfig is portable data — written on one machine and used on another is most of the point of
this tool — so "works where it was generated" is not the bar.

The original alias is never given up. `Host` takes several patterns, so both are written, and
the ASCII one comes **second**: if the original ever becomes valid everywhere, the file must not
have quietly trained people onto the derived name.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "src")

from termius_export.model import AliasAllocator, Host, Model, ascii_slug, is_ssh_safe
from termius_export.normalize import build_model
from termius_export.verify import verify_openssh
from termius_export.writers import WriteContext
from termius_export.writers.openssh import OpenSshWriter


class AsciiSlugTests(unittest.TestCase):
    def test_a_trailing_non_ascii_run_is_dropped(self):
        self.assertEqual(ascii_slug("srv01示例主机"), "srv01")

    def test_interior_runs_collapse_to_a_single_separator(self):
        """Otherwise this comes out as "app-_-_-192.0.2.1"."""
        self.assertEqual(ascii_slug("app-测试-示例-192.0.2.1"), "app-192.0.2.1")

    def test_an_all_non_ascii_label_yields_nothing(self):
        self.assertEqual(ascii_slug("示例主机名"), "")

    def test_an_already_safe_alias_is_returned_unchanged(self):
        self.assertEqual(ascii_slug("web-01.prod_a"), "web-01.prod_a")

    def test_a_leading_dash_is_stripped(self):
        """ssh refuses a destination starting with "-", and would read it as an option first."""
        self.assertEqual(ascii_slug("-leading"), "leading")

    def test_punctuation_only_yields_nothing(self):
        """Accepted by ssh, but not a name anyone can use. Let the caller fall back."""
        self.assertEqual(ascii_slug("..._..."), "")

    def test_empty_yields_nothing(self):
        self.assertEqual(ascii_slug(""), "")

    def test_long_values_are_truncated(self):
        self.assertEqual(len(ascii_slug("a" * 100)), 64)


class IsSshSafeTests(unittest.TestCase):
    def test_accepts_what_ssh_accepts(self):
        # Every one of these was checked against a real ssh rather than reasoned about.
        for alias in ("web-01.prod_a", "1abc", "_abc", ".abc", "a..b", "____", "abc-"):
            self.assertTrue(is_ssh_safe(alias), alias)

    def test_rejects_non_ascii(self):
        self.assertFalse(is_ssh_safe("中文主机"))

    def test_rejects_a_leading_dash(self):
        self.assertFalse(is_ssh_safe("-abc"))

    def test_rejects_characters_slug_would_have_removed(self):
        for alias in ("a b", "a@b"):
            self.assertFalse(is_ssh_safe(alias), alias)


class TakeAsciiTests(unittest.TestCase):
    def test_labels_that_strip_to_the_same_stem_do_not_collide(self):
        """Three different labels all reduce to "GW"; they must stay three different aliases."""
        allocator = AliasAllocator()
        stems = [allocator.take_ascii(label) for label in ("GW-示例", "测试GW节点", "备用GW节点")]
        self.assertEqual(stems, ["GW", "GW-2", "GW-3"])

    def test_an_ascii_alias_cannot_take_another_hosts_primary_alias(self):
        allocator = AliasAllocator()
        self.assertEqual(allocator.take("srv01"), "srv01")
        self.assertEqual(allocator.take_ascii("srv01示例主机"), "srv01-2")

    def test_falls_back_to_the_next_candidate_when_the_first_strips_empty(self):
        allocator = AliasAllocator()
        self.assertEqual(allocator.take_ascii("示例主机名", "192.0.2.30"), "192.0.2.30")

    def test_falls_back_to_the_default_when_every_candidate_strips_empty(self):
        allocator = AliasAllocator()
        self.assertEqual(allocator.take_ascii("中文", "日本語", fallback="host"), "host")


class HostAliasesTests(unittest.TestCase):
    def test_a_safe_alias_has_one_pattern(self):
        h = Host(id="1", alias="demo", label="demo", address="10.0.0.1")
        self.assertEqual(h.aliases, ["demo"])

    def test_the_ascii_alias_comes_second(self):
        h = Host(id="1", alias="中文主机", label="中文主机", address="10.0.0.1", ascii_alias="host-1")
        self.assertEqual(h.aliases, ["中文主机", "host-1"])


class OpenSshDualPatternTests(unittest.TestCase):
    def _config(self, host):
        return OpenSshWriter().write(Model(hosts=[host]), WriteContext(include_secrets=True, key_paths={}))[0].content

    def test_both_patterns_are_written_original_first(self):
        host = Host(id="1", alias="srv01示例主机", label="srv01示例主机", address="10.0.0.1", ascii_alias="srv01")
        self.assertIn("Host srv01示例主机 srv01\n", self._config(host))

    def test_a_safe_alias_is_written_alone(self):
        """No churn for the users whose output was already fine."""
        host = Host(id="1", alias="demo", label="demo", address="10.0.0.1")
        self.assertIn("Host demo\n", self._config(host))


class NormalizeAllocationOrderTests(unittest.TestCase):
    """Every primary alias is allocated before any ASCII fallback is.

    Interleaving the two passes would let a derived name take a name another host wanted for
    itself: the plain "srv01" host below is read *second*, so a single-pass loop would hand
    "srv01" to the CJK host's fallback and push the real "srv01" to "srv01-2" -- a host renamed because of
    an unrelated one that happened to be stored earlier.
    """

    class _Tables:
        def __init__(self, tables):
            self.tables = tables
            self.counts_before_dedup = {name: len(rows) for name, rows in tables.items()}

    class _NoopDecryptor:
        """Stands in for crypto.Decryptor, which the test suite must not import.

        build_model only ever calls walk() and reads stats, so this is the whole contract.
        """

        stats = {"decrypted": 0, "plain": 0, "failed": 0}

        def walk(self, node):
            return node

    def _model(self, rows):
        return build_model(self._Tables({"hosts": rows}), self._NoopDecryptor())

    def test_a_derived_alias_does_not_displace_a_real_one(self):
        model = self._model(
            [
                {"id": "1", "label": "srv01示例主机", "address": "10.0.0.1"},
                {"id": "2", "label": "srv01", "address": "10.0.0.2"},
            ]
        )
        by_label = {h.label: h for h in model.hosts}
        self.assertEqual(by_label["srv01"].alias, "srv01")
        self.assertEqual(by_label["srv01"].ascii_alias, "")
        self.assertEqual(by_label["srv01示例主机"].ascii_alias, "srv01-2")

    def test_an_unnamed_non_ascii_host_falls_back_to_its_address(self):
        model = self._model([{"id": "1", "label": "示例主机名", "address": "192.0.2.30"}])
        self.assertEqual(model.hosts[0].ascii_alias, "192.0.2.30")

    def test_ascii_hosts_get_no_second_pattern(self):
        model = self._model([{"id": "1", "label": "web-01", "address": "10.0.0.1"}])
        self.assertEqual(model.hosts[0].ascii_alias, "")
        self.assertEqual(model.hosts[0].aliases, ["web-01"])


@unittest.skipUnless(shutil.which("ssh"), "ssh not installed")
class DualPatternVerificationTests(unittest.TestCase):
    """A host is reachable if *any* of its patterns works, and every pattern ssh accepts must
    still resolve to the right values.

    A leading dash stands in for the real-world case here: ssh refuses it in every locale and on
    every libc, whereas CJK depends on both, so pinning the test to CJK would make it pass or
    fail depending on where it runs.
    """

    def _by_name(self, config, model):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sshconfig"
            path.write_text(config, encoding="utf-8", newline="\n")
            return {c.name: c for c in verify_openssh(path, model)}

    def test_an_ascii_fallback_makes_a_refused_host_reachable(self):
        model = Model(hosts=[Host(id="1", alias="-orig", label="x", address="10.0.0.1", ascii_alias="orig")])
        checks = self._by_name("Host -orig orig\n    HostName 10.0.0.1\n", model)
        self.assertIs(checks["openssh: alias accepted by ssh"].passed, True)
        self.assertIn("1 only via their ASCII alias", checks["openssh: alias accepted by ssh"].detail)
        self.assertIs(checks["openssh: per-host readback"].passed, True)

    def test_a_wrong_value_on_the_fallback_pattern_is_still_caught(self):
        """The fallback must not become an unchecked back door."""
        model = Model(hosts=[Host(id="1", alias="-orig", label="x", address="10.0.0.1", ascii_alias="orig")])
        checks = self._by_name("Host -orig orig\n    HostName 10.9.9.9\n", model)
        self.assertIs(checks["openssh: per-host readback"].passed, False)
        self.assertIn("orig: hostname", checks["openssh: per-host readback"].detail)

    def test_a_host_with_no_usable_pattern_still_fails(self):
        model = Model(hosts=[Host(id="1", alias="-orig", label="x", address="10.0.0.1")])
        checks = self._by_name("Host -orig\n    HostName 10.0.0.1\n", model)
        self.assertIs(checks["openssh: alias accepted by ssh"].passed, False)

    def test_a_leading_dash_alias_is_not_parsed_as_an_option(self):
        """Without "--", ssh reads "-orig" as "-o rig" and blames the config file instead."""
        model = Model(hosts=[Host(id="1", alias="-orig", label="x", address="10.0.0.1")])
        checks = self._by_name("Host -orig\n    HostName 10.0.0.1\n", model)
        detail = checks["openssh: alias accepted by ssh"].detail
        self.assertNotIn("no argument after keyword", detail)
        self.assertIn("invalid characters", detail)


if __name__ == "__main__":
    unittest.main()
