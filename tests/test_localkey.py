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


from termius_export import localkey


class ImportSafetyTests(unittest.TestCase):
    def test_backend_exists(self):
        # ctypes.wintypes raises on non-Windows, so it must never be imported at module
        # scope. If importing this module fails on Linux, the Windows code leaked its guard.
        self.assertTrue(hasattr(localkey, "_from_credential_manager"))

    def test_credential_backend_returns_none_off_windows(self):
        if sys.platform == "win32":
            self.skipTest("Windows has a real Credential Manager")
        self.assertIsNone(localkey._from_credential_manager("Termius"))

    def test_candidate_services_still_contains_the_measured_windows_service(self):
        # Measured on a real Windows install: target=Termius/localKey
        self.assertIn("Termius", localkey.CANDIDATE_SERVICES)


@unittest.skipUnless(sys.platform == "win32", "requires Windows Credential Manager")
class LiveCredentialManagerTests(unittest.TestCase):
    def test_reads_the_termius_local_key(self):
        value = localkey._from_credential_manager("Termius")
        self.assertIsNotNone(value, "no Termius/localKey credential found")
        self.assertTrue(
            _looks_like_local_key(value),
            f"credential decoded to something that is not a 32-byte key: {len(value)} chars",
        )

    def test_find_local_key_reports_its_source(self):
        key, source = localkey.find_local_key()
        self.assertTrue(_looks_like_local_key(key))
        self.assertIn("Credential Manager", source)


if __name__ == "__main__":
    unittest.main()
