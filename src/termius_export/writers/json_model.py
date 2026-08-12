"""The normalized model itself.

Doubles as a human-readable inventory and as input for other tools to build on.

verified = roundtrip: read back with json.load and compared item by item.
"""

from __future__ import annotations

import dataclasses
import json

from ..model import Model
from . import OutputFile, WriteContext


class JsonWriter:
    name = "json"
    title = "Normalized JSON model"
    verified = "roundtrip"

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]:
        def redact(value: str) -> str:
            if ctx.include_secrets:
                return value
            return "<omitted>" if value else ""

        payload = {
            "model_version": model.model_version,
            "source": model.source,
            "stats": model.stats(),
            "hosts": [
                {
                    "alias": h.alias,
                    "label": h.label,
                    "address": h.address,
                    "port": h.port,
                    "username": h.username,
                    "auth": h.auth,
                    "password": redact(h.password),
                    "group": h.group,
                    "tags": h.tags,
                    "identity_file": ctx.key_path(h.key),
                    "key": None if not h.key else {"label": h.key.label, "has_passphrase": h.key.has_passphrase},
                    "proxy": None
                    if not h.proxy
                    else {**dataclasses.asdict(h.proxy), "password": redact(h.proxy.password)},
                    "agent_forward": h.agent_forward,
                    "forwards": [dataclasses.asdict(f) for f in h.forwards],
                    "label_was_empty": h.label_was_empty,
                }
                for h in model.hosts
            ],
            "keys": [
                {
                    "label": k.label,
                    "file": ctx.key_path(k),
                    "has_passphrase": k.has_passphrase,
                    "passphrase": redact(k.passphrase),
                    "linked": k.linked,
                }
                for k in model.keys
            ],
        }

        return [
            OutputFile(
                path="export.json",
                content=json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                mode=0o600,
            )
        ]
