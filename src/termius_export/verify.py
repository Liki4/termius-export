"""Self-verification of generated output.

Principle: anything that can be falsified locally must actually be run, not eyeballed.
Anything that cannot be verified offline (a real Tabby import, say) is reported as skipped —
never dressed up as a pass.
"""

from __future__ import annotations

import csv
import json
import pathlib
import shutil
import subprocess
from dataclasses import dataclass

from .model import Model


@dataclass
class Check:
    name: str
    #: True = passed, False = failed, None = skipped (cannot be verified offline)
    passed: bool | None
    detail: str = ""


def _ssh_config_value(out: str, field: str) -> str:
    for line in out.splitlines():
        if line.startswith(field + " "):
            return line[len(field) + 1 :].strip()
    return ""


def verify_openssh(path: pathlib.Path, model: Model) -> list[Check]:
    if not shutil.which("ssh"):
        return [Check("openssh: ssh -G parse", None, "ssh not available, skipped")]
    if not model.hosts:
        return [Check("openssh: ssh -G parse", None, "no hosts to verify")]

    try:
        subprocess.run(
            ["ssh", "-G", "-F", str(path), model.hosts[0].alias],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        first = (exc.stderr or "").strip().splitlines()
        return [Check("openssh: ssh -G parse", False, first[0] if first else "ssh rejected the config")]

    checks = [Check("openssh: ssh -G parse", True, "accepted by ssh itself")]

    mismatches = []
    for h in model.hosts:
        if not h.address:
            continue
        out = subprocess.run(
            ["ssh", "-G", "-F", str(path), h.alias],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        ).stdout
        if _ssh_config_value(out, "hostname") != h.address:
            mismatches.append(f"{h.alias}: hostname")
        elif _ssh_config_value(out, "port") != str(h.port):
            mismatches.append(f"{h.alias}: port")
        elif h.username and _ssh_config_value(out, "user") != h.username:
            mismatches.append(f"{h.alias}: user")

    checks.append(
        Check("openssh: per-host readback", True, f"all {len(model.hosts)} hosts match")
        if not mismatches
        else Check("openssh: per-host readback", False, "; ".join(mismatches[:5]))
    )
    return checks


def verify_json(path: pathlib.Path, model: Model) -> list[Check]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [Check("json: parse", False, str(exc))]
    if len(data.get("hosts", [])) != len(model.hosts):
        return [Check("json: host count", False, f"file {len(data.get('hosts', []))} vs model {len(model.hosts)}")]
    if len(data.get("keys", [])) != len(model.keys):
        return [Check("json: key count", False, f"file {len(data.get('keys', []))} vs model {len(model.keys)}")]
    return [Check("json: parse and counts", True, f"{len(model.hosts)} hosts / {len(model.keys)} keys")]


def verify_csv(path: pathlib.Path, model: Model) -> list[Check]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if len(rows) != len(model.hosts):
        return [Check("csv: row count", False, f"file {len(rows)} vs model {len(model.hosts)}")]
    addresses = {h.address for h in model.hosts}
    missing = [r for r in rows if r.get("Hostname") not in addresses]
    if missing:
        return [Check("csv: Hostname column", False, f"{len(missing)} rows do not match the model")]
    return [Check("csv: parse and row compare", True, f"{len(rows)} rows, all addresses match")]


def verify_tabby(path: pathlib.Path, model: Model) -> list[Check]:
    text = path.read_text(encoding="utf-8")
    entries = len([ln for ln in text.splitlines() if ln.startswith("  - id: ")])
    if entries != len(model.hosts):
        return [Check("tabby: entry count", False, f"file {entries} vs model {len(model.hosts)}")]

    unbalanced = [ln for ln in text.splitlines() if ln.count('"') % 2]
    if unbalanced:
        return [Check("tabby: quote balance", False, f"{len(unbalanced)} lines have unbalanced quotes")]

    return [
        Check("tabby: structural check", True, f"{entries} profiles, quotes balanced"),
        Check("tabby: round-trip import", None, "not verified - requires importing into a real Tabby"),
    ]


def verify_termix(path: pathlib.Path, model: Model) -> list[Check]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [Check("termix: parse", False, str(exc))]

    hosts = data.get("hosts", [])
    if len(hosts) != len(model.hosts):
        return [Check("termix: host count", False, f"file {len(hosts)} vs model {len(model.hosts)}")]

    # normalizeImportedHost requires an address; entries without one are unusable.
    no_ip = [h for h in hosts if not h.get("ip")]
    if no_ip:
        return [Check("termix: required ip field", False, f"{len(no_ip)} hosts have no ip")]

    # Mirrors the whitelist enforced by /host/bulk-import, which is stricter than the
    # SSHHost type (the route does not accept "agent").
    valid_auth = {"password", "key", "credential", "none", "opkssh", "tailscale", "vault"}
    bad_auth = [h.get("name") for h in hosts if h.get("authType") not in valid_auth]
    if bad_auth:
        return [Check("termix: authType domain", False, f"invalid: {', '.join(map(str, bad_auth[:5]))}")]

    bad_tunnel = [
        t.get("tunnelType")
        for h in hosts
        for t in h.get("tunnelConnections", [])
        if t.get("tunnelType") not in ("local", "remote")
    ]
    if bad_tunnel:
        return [Check("termix: tunnelType domain", False, f"invalid: {bad_tunnel[:5]}")]

    # Anything the format cannot represent must be reported, never silently dropped.
    # Count against what was actually emitted, not against the model: the
    # --http-proxy-as-socks5 opt-in changes which proxies do make it into the file.
    by_name = {h.get("name"): h for h in hosts}
    lost_proxies = sum(
        1 for h in model.hosts if h.proxy and not (by_name.get(h.label or h.alias) or {}).get("socks5Host")
    )
    lost_forwards = sum(1 for h in model.hosts for f in h.forwards if f.type == "Dynamic")
    detail = f"{len(hosts)} hosts, schema domains valid"
    if lost_proxies or lost_forwards:
        detail += f"; {lost_proxies + lost_forwards} setting(s) unrepresentable, listed in termix-hosts.README.txt"

    return [
        Check("termix: schema and counts", True, detail),
        Check(
            "termix: round-trip import",
            None,
            "verified manually against Termix 2.6.1; cannot be re-checked offline on each run",
        ),
    ]


def verify_known_hosts(path: pathlib.Path, model: Model) -> list[Check]:
    """Look each entry back up with ssh-keygen -F, i.e. OpenSSH's own parser."""
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln and not ln.startswith("#")]
    if len(lines) != len(model.known_hosts):
        return [Check("known_hosts: entry count", False, f"file {len(lines)} vs model {len(model.known_hosts)}")]

    if not shutil.which("ssh-keygen"):
        return [Check("known_hosts: ssh-keygen lookup", None, "ssh-keygen not available, skipped")]

    missing = []
    for entry in model.known_hosts:
        first_host = entry.hostnames.split(",")[0]
        r = subprocess.run(
            ["ssh-keygen", "-F", first_host, "-f", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if r.returncode != 0:
            missing.append(first_host)
    if missing:
        return [Check("known_hosts: ssh-keygen lookup", False, f"not found: {', '.join(missing[:5])}")]
    return [Check("known_hosts: ssh-keygen lookup", True, f"all {len(lines)} entries resolve via OpenSSH")]


VERIFIERS = {
    "sshconfig": verify_openssh,
    "export.json": verify_json,
    "hosts.csv": verify_csv,
    "tabby-profiles.yaml": verify_tabby,
    "termix-hosts.json": verify_termix,
    "known_hosts": verify_known_hosts,
}


def verify_key_files(out_dir: pathlib.Path, model: Model) -> list[Check]:
    """Confirm with ssh-keygen that the exported private keys really parse."""
    if not shutil.which("ssh-keygen"):
        return [Check("keys: ssh-keygen parse", None, "ssh-keygen not available, skipped")]

    files = [
        p
        for p in out_dir.rglob("*")
        if p.is_file() and p.suffix not in (".pub", ".txt") and p.parent.name in ("keys", "keys-unlinked")
    ]
    if not files:
        return [Check("keys: ssh-keygen parse", None, "no private keys exported")]

    bad = []
    for f in files:
        r = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(f)],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        if "SHA256" not in r.stdout:
            bad.append(f.name)
    if bad:
        return [Check("keys: ssh-keygen parse", False, f"unparseable: {', '.join(bad[:5])}")]
    return [Check("keys: ssh-keygen parse", True, f"all {len(files)} private keys parse")]


def verify_outputs(out_dir: pathlib.Path, model: Model) -> list[Check]:
    checks: list[Check] = []
    for filename, fn in VERIFIERS.items():
        p = out_dir / filename
        if p.exists():
            checks.extend(fn(p, model))
    checks.extend(verify_key_files(out_dir, model))
    return checks
