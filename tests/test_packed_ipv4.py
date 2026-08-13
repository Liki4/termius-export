"""Termius stores some addresses as a packed 32-bit integer.

Found in a real 213-host export: two hosts had address "3221226008" rather than "192.0.2.24".
ssh copes, because inet_aton accepts a bare 32-bit number and canonicalises it - which is why
the generated sshconfig worked while self-verification reported a mismatch. The other writers
feed clients that do not cope: Node's net.connect treats "3221226008" as a name to resolve, and
the lookup fails.

Expanding it is lossless and unambiguous: RFC 1123 forbids an all-numeric top-level label, so
an all-digit address cannot be a legal DNS name.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.model import expand_packed_ipv4


class ExpandPackedIpv4Tests(unittest.TestCase):
    def test_expands_the_addresses_from_the_real_export(self):
        self.assertEqual(expand_packed_ipv4("3221226008"), "192.0.2.24")
        self.assertEqual(expand_packed_ipv4("3221226010"), "192.0.2.26")

    def test_matches_what_ssh_resolves(self):
        # ssh -G on "HostName 3221226008" prints "hostname 192.0.2.24"; the model must agree.
        self.assertEqual(expand_packed_ipv4("3221226008"), "192.0.2.24")

    def test_leaves_dotted_quad_untouched(self):
        self.assertEqual(expand_packed_ipv4("10.0.0.1"), "10.0.0.1")

    def test_leaves_hostnames_untouched(self):
        for value in ("example.com", "db-01", "host4", "xn--fsq.com"):
            self.assertEqual(expand_packed_ipv4(value), value)

    def test_leaves_ipv6_untouched(self):
        self.assertEqual(expand_packed_ipv4("::1"), "::1")
        self.assertEqual(expand_packed_ipv4("fe80::1%eth0"), "fe80::1%eth0")

    def test_leaves_empty_untouched(self):
        self.assertEqual(expand_packed_ipv4(""), "")

    def test_leaves_out_of_range_numbers_untouched(self):
        # Larger than 2**32-1 cannot be a packed IPv4, so it is left exactly as found rather
        # than being silently mangled.
        self.assertEqual(expand_packed_ipv4("4294967296"), "4294967296")
        self.assertEqual(expand_packed_ipv4("99999999999999"), "99999999999999")

    def test_boundaries(self):
        self.assertEqual(expand_packed_ipv4("0"), "0.0.0.0")
        self.assertEqual(expand_packed_ipv4("4294967295"), "255.255.255.255")

    def test_matches_inet_aton_for_small_numbers(self):
        # inet_aton("22") is 0.0.0.22, and ssh behaves that way, so the model agrees rather
        # than inventing a different rule.
        self.assertEqual(expand_packed_ipv4("22"), "0.0.0.22")

    def test_non_ascii_digits_are_not_treated_as_numbers(self):
        # str.isdigit() is true for these; int() would raise or, worse, succeed.
        self.assertEqual(expand_packed_ipv4("٣٦٩"), "٣٦٩")

    def test_negative_and_signed_values_are_untouched(self):
        self.assertEqual(expand_packed_ipv4("-1"), "-1")
        self.assertEqual(expand_packed_ipv4("+3221226008"), "+3221226008")


if __name__ == "__main__":
    unittest.main()
