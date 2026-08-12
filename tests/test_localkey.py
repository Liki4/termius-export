"""localKey retrieval.

The blob decoding tests matter because CredentialBlob is raw bytes with no declared encoding.
Rather than assume keytar's UTF-8, the decoder disambiguates using the key's known shape -
base64 of exactly 32 bytes - the same technique that produced the cipher format.
"""

import base64
import sys
import unittest

sys.path.insert(0, "src")

from termius_export.localkey import _decode_credential_blob, _looks_like_local_key

KEY = base64.b64encode(bytes(range(32))).decode("ascii")


class LooksLikeLocalKeyTests(unittest.TestCase):
    def test_accepts_base64_of_exactly_32_bytes(self):
        self.assertTrue(_looks_like_local_key(KEY))

    def test_rejects_base64_of_31_bytes(self):
        self.assertFalse(_looks_like_local_key(base64.b64encode(bytes(31)).decode("ascii")))

    def test_rejects_base64_of_33_bytes(self):
        self.assertFalse(_looks_like_local_key(base64.b64encode(bytes(33)).decode("ascii")))

    def test_rejects_non_base64(self):
        self.assertFalse(_looks_like_local_key("not base64 at all!!"))

    def test_rejects_empty_string(self):
        self.assertFalse(_looks_like_local_key(""))


class DecodeCredentialBlobTests(unittest.TestCase):
    def test_decodes_utf8_blob(self):
        self.assertEqual(_decode_credential_blob(KEY.encode("utf-8")), (KEY, "utf-8"))

    def test_decodes_utf16le_blob(self):
        self.assertEqual(_decode_credential_blob(KEY.encode("utf-16-le")), (KEY, "utf-16-le"))

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(_decode_credential_blob(f"  {KEY}\r\n".encode("utf-8")), (KEY, "utf-8"))

    def test_unrecognised_blob_is_returned_with_an_explicit_label(self):
        value, encoding = _decode_credential_blob(b"garbage")
        self.assertEqual(value, "garbage")
        self.assertIn("unvalidated", encoding)

    def test_does_not_raise_on_undecodable_bytes(self):
        value, encoding = _decode_credential_blob(b"\xff\xfe\x00garbage")
        self.assertIsInstance(value, str)
        self.assertIn("unvalidated", encoding)


if __name__ == "__main__":
    unittest.main()
