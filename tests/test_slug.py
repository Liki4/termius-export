"""Aliases have to survive being typed at ssh.

``slug`` feeds the OpenSSH writer's ``Host`` pattern, so every character it lets through ends
up in a destination someone types. ``@`` is the one that fails silently rather than loudly:
ssh reads it as the user separator, so ``Host root@gateway`` plus ``ssh root@gateway`` resolves
to user ``root`` on a host named ``gateway`` - a different machine, no error, no warning.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.model import AliasAllocator, file_slug, slug


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


class FileSlugTests(unittest.TestCase):
    """``slug`` output is safe to type at ssh; it is not safe to use as a filename.

    A key's ``file_base`` becomes one path component under ``keys/``. Three shapes that
    ``slug`` happily produces are not names at all at that position, and every one of them
    fails silently rather than loudly - which is the category this project treats as worst.
    """

    def test_a_normal_label_is_untouched(self):
        """The overwhelmingly common case. No churn for anyone."""
        self.assertEqual(file_slug("web-01.prod_a", "key_7"), "web-01.prod_a")

    def test_dot_falls_back(self):
        """``keys/.`` *is* ``keys/``. Writing there replaces the directory with a file."""
        self.assertEqual(file_slug(".", "key_7"), "key_7")

    def test_dotdot_falls_back(self):
        """``keys/..`` is the output directory itself; writing there raises IsADirectoryError."""
        self.assertEqual(file_slug("..", "key_7"), "key_7")

    def test_a_windows_device_name_falls_back(self):
        """On Windows ``keys/NUL`` is the null device: the write succeeds and the key vanishes.

        No error, no file, no warning - and this project runs its suite on Windows precisely
        because that class of failure is invisible from Linux.
        """
        for reserved in ("NUL", "nul", "CON", "com1", "LPT9", "aux"):
            self.assertEqual(file_slug(reserved, "key_7"), "key_7", reserved)

    def test_a_device_name_with_an_extension_still_falls_back(self):
        """Windows reserves the stem, not the whole name: NUL.pem is also the null device."""
        self.assertEqual(file_slug("nul.pem", "key_7"), "key_7")

    def test_a_device_name_as_a_substring_is_fine(self):
        """Only the exact stem is reserved. "nullable" and "console" are ordinary names."""
        self.assertEqual(file_slug("nullable", "key_7"), "nullable")
        self.assertEqual(file_slug("console", "key_7"), "console")

    def test_a_trailing_dot_is_dropped(self):
        """Windows silently strips trailing dots, so "backup." and "backup" are one file.

        Dropping it here makes the collision visible to the allocator instead of letting the
        filesystem merge two keys behind its back.
        """
        self.assertEqual(file_slug("backup.", "key_7"), "backup")

    def test_a_name_that_is_only_dots_falls_back(self):
        self.assertEqual(file_slug("...", "key_7"), "key_7")

    def test_empty_falls_back(self):
        self.assertEqual(file_slug("", "key_7"), "key_7")


class AliasCollisionTests(unittest.TestCase):
    def test_aliases_that_differ_only_by_an_at_sign_do_not_merge(self):
        """Replacing a character must not quietly fold two hosts onto one alias."""
        allocator = AliasAllocator()
        self.assertEqual(allocator.take("root@gw"), "root_gw")
        self.assertEqual(allocator.take("root_gw"), "root_gw-2")


if __name__ == "__main__":
    unittest.main()
