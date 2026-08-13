"""The on-the-wire shape of an encrypted field, with no dependency on a crypto library.

Split from ``crypto`` so it can be tested. ``crypto`` imports PyNaCl at module scope, which
puts it out of reach of the test suite, and the rule implemented here is the one this project
is least willing to get wrong::

    base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305(ciphertext + MAC) )

An encrypted field is identified by its **version header**, never by a "looks like base64"
heuristic. Heuristics fail in both directions — they misclassify ordinary base64 payloads as
ciphertext, and they treat a successfully decrypted empty string as a failure.

``crypto`` owns everything that needs a key; this module owns everything that does not.
"""

from __future__ import annotations

import base64

#: The only version header observed so far. Anything else means Termius changed its scheme,
#: which must be reported loudly rather than guessed at.
KNOWN_HEADER = b"\x04\x01"

NONCE_SIZE = 24
MAC_SIZE = 16
#: Ciphertext length for empty plaintext: 2-byte header + 24-byte nonce + 16-byte MAC.
MIN_CIPHERTEXT_LEN = len(KNOWN_HEADER) + NONCE_SIZE + MAC_SIZE


def decode_candidate(value) -> bytes | None:
    """Base64-decode ``value`` if it could be an envelope *by length alone*, else None.

    Split from the header check so a caller that cares about an unfamiliar header — ``crypto``
    has to raise on one — can see the decoded bytes without decoding twice.
    """
    if not isinstance(value, str) or len(value) < 24 or len(value) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:  # noqa: BLE001 - any decoding problem means "not an envelope"
        return None
    return raw if len(raw) >= MIN_CIPHERTEXT_LEN else None


def has_known_header(raw: bytes) -> bool:
    return raw[: len(KNOWN_HEADER)] == KNOWN_HEADER


def is_envelope(value) -> bool:
    """Whether ``value`` is a field this scheme encrypted, judged by the version header."""
    raw = decode_candidate(value)
    return raw is not None and has_known_header(raw)


def first_ciphertext(node):
    """One encrypted field from anywhere in a nested structure, or None.

    The point is to let a candidate key be *tested* rather than guessed at. Poly1305 gives a
    decisive yes/no on whether a key belongs to a body of data, so which keyring entry to use
    becomes a question that can be answered by trying, instead of inferred from install layout.
    That is the same "check the hypothesis against a known plaintext" move that produced the
    cipher format in the first place.

    Returning a non-envelope here would be quietly disastrous rather than noisy: decrypting a
    plaintext field succeeds under *any* key, so every candidate would validate and key
    selection would silently revert to first-one-wins. Hence the header check, and hence this
    living somewhere it can be tested.
    """
    if isinstance(node, str):
        return node if is_envelope(node) else None
    if isinstance(node, dict):
        node = node.values()
    elif not isinstance(node, (list, tuple)):
        return None
    for item in node:
        found = first_ciphertext(item)
        if found is not None:
            return found
    return None


def plausible_envelope(raw: bytes) -> bool:
    """Whether unknown-header bytes are worth raising about.

    Only lengths in the "overhead + plausible plaintext" range are treated as suspicious, so
    unrelated base64 blobs are not misreported as an unknown cipher version.
    """
    return MIN_CIPHERTEXT_LEN <= len(raw) <= MIN_CIPHERTEXT_LEN + 8192
