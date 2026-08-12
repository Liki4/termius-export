"""Decryption for Termius's field-level encryption.

Format (reverse-engineered; see the "Cipher format" section of CLAUDE.md)::

    base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305(ciphertext + MAC) )

That is a standard NaCl secretbox with a two-byte version header prepended. The key is the
base64-decoded ``localKey`` from the OS keyring, 32 bytes long.

Key design decision: an encrypted field is identified by its **version header**, not by a
"looks like base64" heuristic. Heuristics fail in both directions — they misclassify ordinary
base64 payloads as ciphertext, and they treat a successfully decrypted empty string as a
failure. A header check avoids both.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

import nacl.exceptions
import nacl.secret

#: The only version header observed so far. Anything else means Termius changed its scheme,
#: which must be reported loudly rather than guessed at.
KNOWN_HEADER = b"\x04\x01"

NONCE_SIZE = 24
MAC_SIZE = 16
#: Ciphertext length for empty plaintext: 2-byte header + 24-byte nonce + 16-byte MAC.
MIN_CIPHERTEXT_LEN = len(KNOWN_HEADER) + NONCE_SIZE + MAC_SIZE


class UnknownCipherVersion(Exception):
    """An unrecognised version header: upstream changed the encryption format."""

    def __init__(self, header: bytes) -> None:
        super().__init__(
            f"Unknown cipher version header {header.hex()} (only {KNOWN_HEADER.hex()} is known). "
            "Termius may have changed its encryption scheme; do not trust this export."
        )
        self.header = header


class DecryptionFailed(Exception):
    """Header matched but the MAC did not verify — wrong key, or corrupted data."""


@dataclass
class Decryptor:
    """Decrypts individual fields and records statistics for post-export self-checks."""

    key: bytes
    strict: bool = True
    stats: dict[str, int] = field(default_factory=lambda: {"decrypted": 0, "plain": 0, "failed": 0})

    def __post_init__(self) -> None:
        if len(self.key) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError(f"localKey must be {nacl.secret.SecretBox.KEY_SIZE} bytes, got {len(self.key)}")
        self._box = nacl.secret.SecretBox(self.key)

    @classmethod
    def from_base64(cls, value: str, *, strict: bool = True) -> Decryptor:
        return cls(key=base64.b64decode(value.strip()), strict=strict)

    def _envelope(self, value: str) -> bytes | None:
        """Return the decoded envelope bytes, or None if this field is not encrypted."""
        if len(value) < 24 or len(value) % 4 != 0:
            return None
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception:
            return None
        if len(raw) < MIN_CIPHERTEXT_LEN:
            return None
        if raw[: len(KNOWN_HEADER)] != KNOWN_HEADER:
            # Shaped like an envelope but with an unfamiliar header. In strict mode, fail
            # rather than silently leaving the field undecrypted.
            if self.strict and _plausible_envelope(raw):
                raise UnknownCipherVersion(raw[: len(KNOWN_HEADER)])
            return None
        return raw

    def field(self, value):
        """Decrypt one field. Non-strings and non-ciphertext are returned unchanged."""
        if not isinstance(value, str):
            return value
        raw = self._envelope(value)
        if raw is None:
            self.stats["plain"] += 1
            return value

        nonce = raw[len(KNOWN_HEADER) : len(KNOWN_HEADER) + NONCE_SIZE]
        body = raw[len(KNOWN_HEADER) + NONCE_SIZE :]
        try:
            plaintext = self._box.decrypt(body, nonce)
        except nacl.exceptions.CryptoError as exc:
            self.stats["failed"] += 1
            if self.strict:
                raise DecryptionFailed("field failed MAC verification; the key may be wrong") from exc
            return value

        self.stats["decrypted"] += 1
        # This may legitimately be an empty string (the user never named the host).
        # Never treat a falsy result as failure.
        return plaintext.decode("utf-8", errors="replace")

    def walk(self, node):
        """Recursively decrypt every string in a nested structure."""
        if isinstance(node, dict):
            return {k: self.walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self.walk(v) for v in node]
        return self.field(node)


def _plausible_envelope(raw: bytes) -> bool:
    """Heuristic for whether unknown-header bytes are worth raising about.

    Only lengths in the "overhead + plausible plaintext" range are treated as suspicious, so
    unrelated base64 blobs are not misreported as an unknown cipher version.
    """
    return MIN_CIPHERTEXT_LEN <= len(raw) <= MIN_CIPHERTEXT_LEN + 8192
