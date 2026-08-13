"""Aliases have to survive being typed at ssh.

``slug`` feeds the OpenSSH writer's ``Host`` pattern, so every character it lets through ends
up in a destination someone types. ``@`` is the one that fails silently rather than loudly:
ssh reads it as the user separator, so ``Host root@gateway`` plus ``ssh root@gateway`` resolves
to user ``root`` on a host named ``gateway`` - a different machine, no error, no warning.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.model import AliasAllocator, slug  # noqa: E402


class SlugTests(unittest.TestCase):
    def test_at_sign_is_replaced(self):
        self.assertEqual(slug("root@gateway", "host"), "root_gateway")

    def test_characters_ssh_accepts_are_left_alone(self):
        self.assertEqual(slug("web-01.prod_a", "host"), "web-01.prod_a")

    def test_spaces_and_punctuation_are_replaced(self):
        self.assertEqual(slug("prod box (eu)", "host"), "prod_box_eu")

    def test_empty_falls_back(self):
        self.assertEqual(slug("", "fallback"), "fallback")

    def test_long_values_are_truncated(self):
        self.assertEqual(len(slug("a" * 100, "host")), 64)

    def test_non_ascii_is_preserved(self):
        """Deliberate, not an oversight: Python's ``\\w`` is Unicode-aware.

        Whether ssh then *accepts* such an alias is locale-dependent and is a separate
        question from what ``slug`` should strip; it is tracked upstream rather than fixed by
        widening this pattern.
        """
        self.assertEqual(slug("生产服务器", "host"), "生产服务器")


class AliasCollisionTests(unittest.TestCase):
    def test_aliases_that_differ_only_by_an_at_sign_do_not_merge(self):
        """Replacing a character must not quietly fold two hosts onto one alias."""
        allocator = AliasAllocator()
        self.assertEqual(allocator.take("root@gw"), "root_gw")
        self.assertEqual(allocator.take("root_gw"), "root_gw-2")


if __name__ == "__main__":
    unittest.main()
