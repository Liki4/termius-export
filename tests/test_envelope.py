"""Envelope detection, and the sampler that key selection depends on.

`first_ciphertext` picks the field a candidate key is tested against. If it ever returned
something that is *not* ciphertext, decryption of that field would succeed under any key at
all, every candidate would validate, and key selection would silently revert to
first-one-wins — with no error anywhere. That is the failure mode these tests exist for, and
it is why the detection rule lives in a module the suite can import.
"""

import base64
import sys
import unittest

sys.path.insert(0, "src")

from termius_export.envelope import (
    KNOWN_HEADER,
    MIN_CIPHERTEXT_LEN,
    decode_candidate,
    first_ciphertext,
    has_known_header,
    is_envelope,
)


def envelope(plaintext_len=5):
    """A syntactically valid envelope. Nothing here decrypts it, so the body is filler."""
    return base64.b64encode(KNOWN_HEADER + b"n" * 24 + b"m" * (16 + plaintext_len)).decode()


class OverheadTests(unittest.TestCase):
    def test_the_overhead_is_the_number_that_identified_the_algorithm(self):
        """42 = 2 header + 24 nonce + 16 MAC.

        The 24-byte nonce is what ruled out AES-GCM and ChaCha20-Poly1305-IETF, which are both
        12 + 16, and pointed at NaCl secretbox. Pinned because the whole format hangs off it.
        """
        self.assertEqual(MIN_CIPHERTEXT_LEN, 42)


class IsEnvelopeTests(unittest.TestCase):
    def test_accepts_a_well_formed_envelope(self):
        self.assertTrue(is_envelope(envelope()))

    def test_accepts_the_empty_plaintext_case(self):
        """An unnamed host stores an encrypted *empty string*; it is still an envelope."""
        self.assertTrue(is_envelope(envelope(plaintext_len=0)))

    def test_rejects_plain_text(self):
        for value in ("", "example.com", "root", "a" * 100):
            self.assertFalse(is_envelope(value), value)

    def test_rejects_base64_carrying_an_unfamiliar_header(self):
        """Right shape, wrong scheme. Detection is by header, never by "looks like base64"."""
        blob = base64.b64encode(b"\x99\x99" + b"x" * 40).decode()
        self.assertEqual(len(base64.b64decode(blob)), MIN_CIPHERTEXT_LEN)
        self.assertFalse(is_envelope(blob))

    def test_rejects_something_too_short_to_hold_the_overhead(self):
        self.assertFalse(is_envelope(base64.b64encode(KNOWN_HEADER + b"x" * 8).decode()))

    def test_rejects_non_strings(self):
        for value in (None, 22, True, [], {}, b"bytes"):
            self.assertFalse(is_envelope(value), repr(value))

    def test_decode_candidate_and_header_check_compose_to_is_envelope(self):
        raw = decode_candidate(envelope())
        self.assertIsNotNone(raw)
        self.assertTrue(has_known_header(raw))


class FirstCiphertextTests(unittest.TestCase):
    def test_finds_one_nested_in_dicts_and_lists(self):
        ct = envelope()
        tables = {"hosts": [{"id": 1, "label": "plain", "address": ct}]}
        self.assertEqual(first_ciphertext(tables), ct)

    def test_returns_none_when_nothing_is_encrypted(self):
        """The dangerous case. A plaintext field decrypts under any key, so returning one here
        would make every candidate look valid and quietly disable key selection."""
        tables = {"hosts": [{"id": 1, "label": "plain", "address": "example.com", "port": 22}]}
        self.assertIsNone(first_ciphertext(tables))

    def test_does_not_mistake_an_unfamiliar_header_for_ciphertext(self):
        blob = base64.b64encode(b"\x99\x99" + b"x" * 40).decode()
        self.assertIsNone(first_ciphertext({"t": [{"a": blob}]}))

    def test_survives_scalars_it_cannot_walk(self):
        self.assertIsNone(first_ciphertext({"a": None, "b": 22, "c": True, "d": 1.5, "e": b"x"}))

    def test_returns_none_for_an_empty_profile(self):
        self.assertIsNone(first_ciphertext({}))

    def test_walks_past_plaintext_to_reach_ciphertext(self):
        ct = envelope()
        self.assertEqual(first_ciphertext(["plain", {"x": ["also plain", ct]}]), ct)


if __name__ == "__main__":
    unittest.main()
