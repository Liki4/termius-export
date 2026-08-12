"""Termix bulk-import payload (POST /host/bulk-import, or the Hosts panel importer).

verified = roundtrip

Verified by importing the generated payload into a real Termix 2.6.1 (Flatpak,
com.karmaa.termix) via the Hosts panel and confirming the hosts connect. Coverage of that
check: host fields, key authentication with inline private keys, tunnelConnections, and the
SOCKS5 proxy fields produced by --http-proxy-as-socks5.

Not covered by that check, because the source data had no examples: remote/dynamic tunnels
(only local ones existed), credential-based auth, and non-SSH connection types.

Field names and value domains come from Termix's own source, read at tag v2.6.1::

    src/ui/sidebar/host-export-payload.ts
        ExportPayload, FIELD_GROUP_KEYS, SECRET_KEYS
    src/backend/database/routes/host-normalizers.ts
        normalizeImportedHost  - the authoritative import contract
    src/backend/database/routes/host-bulk-routes.ts
        /host/bulk-import, parseSSHConfig
    src/types/index.ts
        SSHHost, TunnelConnection

Why not just hand Termix our sshconfig? Termix *can* import an SSH config, but its
``parseSSHConfig`` only reads Host / HostName / User / Port / IdentityFile / ProxyJump. Proxy
settings, port forwards, agent forwarding and every credential are dropped on the floor, and
entries without a HostName are skipped entirely. The bulk-import payload carries all of it.

``normalizeImportedHost`` is deliberately permissive (``name``/``label``, ``ip``/``address``/
``host``/``hostname``, ``username``/``user``, ``folder``/``group`` are all accepted). We emit
the canonical spelling of each.

Two things Termix has no representation for. Neither is dropped silently — both are counted,
written into the file header, and surfaced by the writer's ``notes``:

* **Non-SOCKS5 proxies.** Termix models per-host proxies as ``useSocks5`` + ``socks5Host`` /
  ``socks5Port`` / ``socks5Username`` / ``socks5Password``. An HTTP proxy has nowhere to go.
* **Dynamic port forwards.** ``TunnelConnection.tunnelType`` is ``"local" | "remote"`` only.

``keyType`` is left unset on purpose: the field is a free-form string in Termix and we have no
evidence of its accepted values. Omitting is safer than inventing one.
"""

from __future__ import annotations

import json

from ..model import Model
from . import OutputFile, WriteContext

#: Defaults for TunnelConnection's required numeric fields (src/types/index.ts).
TUNNEL_MAX_RETRIES = 3
TUNNEL_RETRY_INTERVAL = 10


class TermixWriter:
    name = "termix"
    title = "Termix bulk-import payload"
    verified = "roundtrip"

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]:
        dropped_proxies: list[str] = []
        converted_proxies: list[str] = []
        dropped_forwards: list[str] = []
        hosts: list[dict] = []

        for h in model.hosts:
            entry: dict = {
                "connectionType": "ssh",
                "name": h.label or h.alias,
                "ip": h.address,
                "port": h.port,
                "username": h.username,
                "folder": h.group,
                "tags": h.tags,
                "pin": False,
            }

            # authType drives which credential fields Termix reads.
            if h.key:
                entry["authType"] = "key"
                key_obj = next((k for k in model.keys if k.id == h.key.id), None)
                if ctx.include_secrets and key_obj:
                    # Termix stores key material inline, not a path on disk.
                    entry["key"] = key_obj.private_key
                    if key_obj.passphrase:
                        entry["keyPassword"] = key_obj.passphrase
            elif h.password:
                entry["authType"] = "password"
                if ctx.include_secrets:
                    entry["password"] = h.password
            else:
                entry["authType"] = "none"

            if h.proxy:
                as_socks5 = h.proxy.kind == "socks5" or (ctx.http_proxy_as_socks5 and h.proxy.kind == "http")
                if h.proxy.kind == "http" and as_socks5:
                    converted_proxies.append(f"{entry['name']} (http -> socks5 on {h.proxy.host}:{h.proxy.port})")
                if as_socks5:
                    entry["useSocks5"] = True
                    entry["socks5Host"] = h.proxy.host
                    entry["socks5Port"] = h.proxy.port
                    if h.proxy.username:
                        entry["socks5Username"] = h.proxy.username
                    if h.proxy.password and ctx.include_secrets:
                        entry["socks5Password"] = h.proxy.password
                else:
                    dropped_proxies.append(f"{entry['name']} ({h.proxy.kind} {h.proxy.host}:{h.proxy.port})")

            tunnels = []
            for f in h.forwards:
                if f.type == "Dynamic":
                    dropped_forwards.append(f"{entry['name']}: dynamic :{f.local_port}")
                    continue
                tunnels.append(
                    {
                        "tunnelType": f.type.lower(),  # "local" | "remote"
                        "bindHost": f.bound_address,
                        "sourcePort": f.local_port,
                        "endpointPort": f.target_port,
                        "endpointHost": f.target_host,
                        "maxRetries": TUNNEL_MAX_RETRIES,
                        "retryInterval": TUNNEL_RETRY_INTERVAL,
                        "autoStart": False,
                    }
                )
            if tunnels:
                entry["tunnelConnections"] = tunnels

            hosts.append(entry)

        payload = {
            "version": "1",
            "exportedAt": model.source.get("exported_at") or "",
            "hosts": hosts,
        }

        header = [
            "// Termix bulk-import payload - generated by termius-export",
            "//",
            "// Import via the Hosts panel importer, or:",
            "//   POST /host/bulk-import   body: this file",
            "//",
            "// Verified against Termix 2.6.1 by round-trip import. Still confirm one host",
            "// connects before relying on the rest - your Termix version may differ.",
        ]
        if converted_proxies:
            header += [
                "//",
                f"// NOTE: {len(converted_proxies)} HTTP proxy setting(s) were written into the SOCKS5",
                "// fields because --http-proxy-as-socks5 was given. This is only correct if the",
                "// proxy is a mixed port that speaks both protocols.",
            ] + [f"//   - {d}" for d in converted_proxies]
        if dropped_proxies:
            header += [
                "//",
                f"// WARNING: {len(dropped_proxies)} proxy setting(s) could not be represented.",
                "// Termix only models SOCKS5 proxies per host (useSocks5/socks5Host/...).",
            ] + [f"//   - {d}" for d in dropped_proxies]
        if dropped_forwards:
            header += [
                "//",
                f"// WARNING: {len(dropped_forwards)} dynamic port forward(s) dropped.",
                '// TunnelConnection.tunnelType is "local" | "remote" only.',
            ] + [f"//   - {d}" for d in dropped_forwards]

        files = [
            OutputFile(
                path="termix-hosts.json",
                content=json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                mode=0o600,
            )
        ]
        # JSON cannot carry comments, so the caveats live in a sidecar file that is always
        # written - the payload itself stays machine-readable.
        files.append(OutputFile(path="termix-hosts.README.txt", content="\n".join(header) + "\n", mode=0o600))
        return files
