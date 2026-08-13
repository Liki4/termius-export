"""The client-agnostic intermediate model.

Writers consume only these structures and never touch Termius's table layout. Supporting a
new client means adding one writer, not re-reading Termius's internals.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

MODEL_VERSION = 1


@dataclass
class Key:
    id: str
    label: str
    file_base: str
    private_key: str
    public_key: str = ""
    passphrase: str = ""
    linked: bool = False

    @property
    def has_passphrase(self) -> bool:
        return bool(self.passphrase)


@dataclass
class Proxy:
    kind: str  # "http" | "socks5" | anything else is passed through verbatim
    host: str
    port: int
    username: str = ""
    password: str = ""


@dataclass
class Forward:
    label: str
    type: str  # "Local" | "Remote" | "Dynamic"
    bound_address: str
    local_port: int
    target_host: str
    target_port: int


@dataclass
class KnownHost:
    """One line of an OpenSSH known_hosts file."""

    hostnames: str
    key: str  # already includes the key type prefix, e.g. "ssh-ed25519 AAAA..."
    marker: str = ""  # "@cert-authority" / "@revoked", usually empty
    comment: str = ""

    def to_line(self) -> str:
        parts = [p for p in (self.marker, self.hostnames, self.key, self.comment) if p]
        return " ".join(parts)


@dataclass
class Host:
    id: str
    alias: str
    label: str
    address: str
    port: int = 22
    username: str = ""
    password: str = ""
    group: str = ""
    key: Key | None = None
    proxy: Proxy | None = None
    agent_forward: bool = False
    forwards: list[Forward] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    #: The source had no name for this host. Termius displays the address in that case,
    #: and alias generation mirrors that behaviour.
    label_was_empty: bool = False
    #: A second, ASCII-only `Host` pattern, set only when `alias` is one ssh may refuse.
    #: Empty when `alias` is already safe everywhere, which is the common case.
    ascii_alias: str = ""

    @property
    def aliases(self) -> list[str]:
        """Every `Host` pattern this host answers to, in the order they are written."""
        return [self.alias, self.ascii_alias] if self.ascii_alias else [self.alias]

    @property
    def auth(self) -> str | None:
        if self.key:
            return "publicKey"
        if self.password:
            return "password"
        return None


@dataclass
class Model:
    hosts: list[Host] = field(default_factory=list)
    keys: list[Key] = field(default_factory=list)
    forwards: list[Forward] = field(default_factory=list)
    known_hosts: list[KnownHost] = field(default_factory=list)
    source: dict = field(default_factory=dict)
    model_version: int = MODEL_VERSION

    @property
    def orphan_keys(self) -> list[Key]:
        return [k for k in self.keys if not k.linked]

    def stats(self) -> dict:
        return {
            "hosts": len(self.hosts),
            "keys": len(self.keys),
            "keys_linked": sum(1 for k in self.keys if k.linked),
            "keys_orphaned": len(self.orphan_keys),
            "hosts_with_key": sum(1 for h in self.hosts if h.key),
            "hosts_with_password": sum(1 for h in self.hosts if h.password),
            "hosts_with_proxy": sum(1 for h in self.hosts if h.proxy),
            "hosts_without_label": sum(1 for h in self.hosts if h.label_was_empty),
            "forwards": len(self.forwards),
            "hosts_with_tags": sum(1 for h in self.hosts if h.tags),
            "known_hosts": len(self.known_hosts),
        }


def expand_packed_ipv4(value: str) -> str:
    """Expand a packed 32-bit IPv4 address into dotted-quad form, leaving anything else alone.

    Termius stores some addresses as the integer form: ``3221226008`` rather than
    ``192.0.2.24``. ssh copes, because ``inet_aton`` accepts a bare 32-bit number, so the
    generated sshconfig works and ``ssh -G`` canonicalises it back to dotted-quad. The other
    writers feed clients that do not cope - Node's ``net.connect`` treats ``"3221226008"`` as a
    name to resolve, and the lookup fails - so Tabby, Termix, CSV and JSON would all carry an
    address their consumer cannot use.

    The expansion is lossless and unambiguous: RFC 1123 forbids an all-numeric top-level
    label, so an all-digit address cannot be a legal DNS name. Values that cannot be a packed
    IPv4 - out of range, signed, non-ASCII digits - are returned untouched rather than
    mangled.
    """
    if not (value.isascii() and value.isdigit()):
        return value
    packed = int(value)
    if packed > 0xFFFFFFFF:
        return value
    return str(ipaddress.IPv4Address(packed))


#: ``@`` is deliberately **not** in the permitted set, even though it is a legal filename
#: character and reads naturally in a label like ``root@gateway``. ssh parses ``@`` in a
#: destination as the user separator, so ``ssh root@gateway`` against a ``Host root@gateway``
#: block resolves to user ``root`` on a host literally named ``gateway`` — a different machine,
#: silently, with no error. Replacing it with ``_`` costs nothing and removes the trap.
_SLUG_STRIP = re.compile(r"[^\w.-]+")


def slug(value: str, fallback: str) -> str:
    s = _SLUG_STRIP.sub("_", str(value or "").strip()).strip("_")
    return (s or fallback)[:64]


#: Reserved by Windows at every position in the filesystem, and reserved *by stem*: ``NUL.pem``
#: is the null device exactly as ``NUL`` is. Opening one succeeds and writes nowhere, so a
#: private key exported under such a name is discarded without an error, a file or a warning.
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


def file_slug(value: str, fallback: str) -> str:
    """A ``slug`` that is also safe to use as a single path component.

    ``slug`` answers "what may appear in a destination someone types at ssh", which is a
    different question from "what may name a file", and it permits three answers to the second
    that are not names at all. All three fail quietly:

    - ``.`` and ``..`` denote the directory itself and its parent, so ``keys/.`` replaces the
      key directory with a file and ``keys/..`` writes into the output root.
    - A Windows device name is opened by the OS rather than created, so the key vanishes.
    - A trailing dot is stripped by Windows, silently merging ``backup.`` and ``backup`` into
      one file. Dropping it here instead hands the collision to the allocator, which can see it.

    ``fallback`` is assumed to be a safe component; every caller derives it from a record id.
    """
    s = slug(value, fallback).rstrip(".")
    if not s or s.split(".")[0].upper() in _WINDOWS_DEVICE_NAMES:
        return fallback
    return s


#: Everything ssh will accept inside a destination. Runs of anything else collapse to a single
#: ``-`` rather than ``_`` so that a label like "cce-<CJK>-<CJK>-192.0.2.1" comes out as
#: "cce-192.0.2.1" instead of "cce-_-_-192.0.2.1".
_ASCII_STRIP = re.compile(r"[^A-Za-z0-9._-]+")

#: An alias ssh will take as a destination. Leading ``-`` is the one edge that fails: ssh
#: rejects it outright ("hostname contains invalid characters"), and an unquoted one would be
#: parsed as an option long before that. Measured, not assumed - ``.abc``, ``_abc``, ``1abc``,
#: ``a..b`` and ``____`` are all accepted.
_SSH_SAFE = re.compile(r"\A[A-Za-z0-9_.][A-Za-z0-9._-]*\Z")


def is_ssh_safe(alias: str) -> bool:
    """Whether ssh will accept ``alias`` as a destination on any platform.

    Deliberately stricter than what the local ``ssh`` happens to allow. A generated sshconfig
    is portable data - produced on one machine and used on another, which is most of the point
    of this tool - and whether a non-ASCII destination is accepted turns out to depend on the C
    library, not on OpenSSH: glibc accepts CJK under every locale, macOS rejects it under any
    UTF-8 one. "Works where it was generated" is not the bar.
    """
    return bool(_SSH_SAFE.match(alias))


def ascii_slug(value: str) -> str:
    """An ASCII-only, ssh-safe form of ``value``, or ``""`` if nothing usable survives."""
    s = _ASCII_STRIP.sub("-", str(value or "").strip())
    s = re.sub(r"-{2,}", "-", s).strip("-")
    s = s[:64].strip("-")
    # A result of only dots and underscores is technically accepted by ssh but is not a name
    # anyone can use; treat it as nothing survived and let the caller fall back.
    return s if any(c.isalnum() for c in s) and is_ssh_safe(s) else ""


class AliasAllocator:
    """Allocates non-colliding Host aliases.

    Both the original and the ASCII alias come from the same allocator, so an ASCII form can
    never collide with another host's primary alias - which would silently route two hosts to
    one entry.
    """

    def __init__(self) -> None:
        self._used: set[str] = set()

    def _allocate(self, root: str) -> str:
        candidate = root
        n = 2
        while candidate in self._used:
            candidate = f"{root}-{n}"
            n += 1
        self._used.add(candidate)
        return candidate

    def take(self, base: str, fallback: str = "host") -> str:
        return self._allocate(slug(base, fallback))

    def take_ascii(self, *candidates: str, fallback: str = "host") -> str:
        """Allocate an ASCII alias from the first candidate that survives stripping.

        Callers pass the label first and the address second: a label stripped of its non-ASCII
        run is the more recognisable name, and falling back to the address mirrors what already
        happens for a host the user never named.
        """
        for candidate in candidates:
            root = ascii_slug(candidate)
            if root:
                return self._allocate(root)
        return self._allocate(fallback)
