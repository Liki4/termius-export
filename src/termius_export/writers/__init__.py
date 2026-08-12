"""Writer plugin interface.

A writer is any object satisfying the ``Writer`` protocol::

    name        short name used on the CLI, e.g. "openssh"
    title       human-readable name
    verified    see below
    write(model, ctx) -> list[OutputFile]

``verified`` must be filled in honestly. It is this project's most basic commitment to its
users:

``roundtrip``
    Output has been read back and validated by the target client (or its official parser).
``upstream-source``
    Fields follow the target client's **type definitions in its own source code**, but no
    import round-trip was performed.
``unverified``
    Guessed from documentation or experience. **This repository does not ship these.** A config
    that is quietly wrong is worse than none at all — get a real sample or the source
    definitions first.

The full procedure for adding a writer is in CLAUDE.md, "Adding a writer".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..model import Model


@dataclass
class OutputFile:
    path: str
    content: str
    mode: int = 0o600


@dataclass
class WriteContext:
    include_secrets: bool
    #: key.id -> absolute path of the private key on disk; empty when not written
    key_paths: dict[str, str]
    #: Opt-in: emit HTTP proxies into targets that only model SOCKS5. Safe only when the
    #: proxy is a mixed port (Clash / mihomo / FlClash speak both on one port); never
    #: assumed by default because it is false for a plain HTTP-CONNECT proxy.
    http_proxy_as_socks5: bool = False

    def key_path(self, key) -> str:
        return self.key_paths.get(getattr(key, "id", ""), "") if key else ""


class Writer(Protocol):
    name: str
    title: str
    verified: str

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]: ...


from .csv_hosts import CsvWriter  # noqa: E402
from .json_model import JsonWriter  # noqa: E402
from .known_hosts import KnownHostsWriter  # noqa: E402
from .openssh import OpenSshWriter  # noqa: E402
from .tabby import TabbyWriter  # noqa: E402
from .termix import TermixWriter  # noqa: E402

WRITERS: list[Writer] = [OpenSshWriter(), JsonWriter(), CsvWriter(), TabbyWriter(), TermixWriter(), KnownHostsWriter()]
BY_NAME = {w.name: w for w in WRITERS}


def resolve(names: list[str] | None) -> list[Writer]:
    if not names or "all" in names:
        return list(WRITERS)
    out = []
    for n in names:
        if n not in BY_NAME:
            raise KeyError(f"unknown writer: {n} (available: {', '.join(BY_NAME)})")
        out.append(BY_NAME[n])
    return out
