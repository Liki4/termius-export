"""Generic CSV.

Column names follow Termius's own import template (Groups / Label / Tags / Hostname /
Protocol / Port / Username / Password), so the file can be fed back into Termius and is
accepted by most other SSH managers.

verified = roundtrip: read back with the standard library csv module and compared field by
field.
"""

from __future__ import annotations

import csv
import io

from ..model import Model
from . import OutputFile, WriteContext

COLUMNS = [
    "Groups",
    "Label",
    "Tags",
    "Hostname",
    "Protocol",
    "Port",
    "Username",
    "Password",
    "IdentityFile",
    "KeyLabel",
    "KeyPassphrase",
    "ProxyType",
    "ProxyHost",
    "ProxyPort",
]


class CsvWriter:
    name = "csv"
    title = "Generic CSV (Termius import template columns)"
    verified = "roundtrip"

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(COLUMNS)
        for h in model.hosts:
            w.writerow(
                [
                    h.group,
                    h.label or h.alias,
                    ",".join(h.tags),
                    h.address,
                    "ssh",
                    h.port,
                    h.username,
                    h.password if ctx.include_secrets else "",
                    ctx.key_path(h.key),
                    h.key.label if h.key else "",
                    (h.key.passphrase if (h.key and ctx.include_secrets) else ""),
                    h.proxy.kind if h.proxy else "",
                    h.proxy.host if h.proxy else "",
                    h.proxy.port if h.proxy else "",
                ]
            )
        return [OutputFile(path="hosts.csv", content=buf.getvalue(), mode=0o600)]
