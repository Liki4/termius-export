"""The client-agnostic intermediate model.

Writers consume only these structures and never touch Termius's table layout. Supporting a
new client means adding one writer, not re-reading Termius's internals.
"""

from __future__ import annotations

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


_SLUG_STRIP = re.compile(r"[^\w.@-]+")


def slug(value: str, fallback: str) -> str:
    s = _SLUG_STRIP.sub("_", str(value or "").strip()).strip("_")
    return (s or fallback)[:64]


class AliasAllocator:
    """Allocates non-colliding Host aliases."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def take(self, base: str, fallback: str = "host") -> str:
        root = slug(base, fallback)
        candidate = root
        n = 2
        while candidate in self._used:
            candidate = f"{root}-{n}"
            n += 1
        self._used.add(candidate)
        return candidate
