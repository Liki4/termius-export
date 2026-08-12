"""Retrieve Termius's ``localKey`` from the OS keyring.

Storage location differs per platform, and the **service name depends on how Termius was
installed**: Termius uses the executable name as the keyring service, so a snap install stores
it under ``termius-app`` while macOS uses ``Termius``. Looking up "Termius" on a snap install
finds nothing — an easy trap.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys

#: Tried in order. First entry covers Linux/snap, the rest cover macOS and older builds.
CANDIDATE_SERVICES = (
    "termius-app",
    "Termius",
    "Termius (MAS)",
    "termius",
    "com.termius-dmg.mac",
)

ACCOUNT = "localKey"

#: localKey is a NaCl secretbox key: base64 of exactly 32 bytes.
LOCAL_KEY_BYTES = 32

#: Which blob encoding actually worked, per service. Reported in the run summary so the first
#: real Windows run measures this instead of leaving it an assumption.
_LAST_BLOB_ENCODING: dict[str, str] = {}


class LocalKeyNotFound(Exception):
    pass


def _looks_like_local_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == LOCAL_KEY_BYTES
    except Exception:  # noqa: BLE001 - any decoding problem means "not a key"
        return False


def _decode_credential_blob(blob: bytes) -> tuple[str, str]:
    """Decode a Windows CredentialBlob into ``(key, encoding_label)``.

    The blob is raw bytes and Credential Manager declares no encoding. keytar writes UTF-8,
    but that cannot be confirmed without a Windows machine, so rather than assume, candidate
    encodings are disambiguated by the key's known shape - the same "use the known plaintext"
    technique that produced the cipher format. The label is reported in the run summary, so
    the first real Windows run turns this from an assumption into a measurement.
    """
    for label in ("utf-8", "utf-16-le"):
        try:
            candidate = blob.decode(label).strip()
        except UnicodeDecodeError:
            continue
        if _looks_like_local_key(candidate):
            return candidate, label
    return blob.decode("utf-8", errors="replace").strip(), "utf-8 (unvalidated)"


def _from_secret_tool(service: str) -> str | None:
    """Linux: the freedesktop Secret Service (implemented by GNOME Keyring and KWallet)."""
    if not shutil.which("secret-tool"):
        return None
    try:
        out = subprocess.run(
            ["secret-tool", "lookup", "service", service, "account", ACCOUNT],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out.stdout.strip() or None


def _from_macos_keychain(service: str) -> str | None:
    if sys.platform != "darwin" or not shutil.which("security"):
        return None
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", ACCOUNT, "-w"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out.stdout.strip() or None


def _from_credential_manager(service: str) -> str | None:
    """Windows: read the generic credential keytar writes.

    ``ctypes`` is used rather than a PowerShell subprocess because ``cmdkey`` cannot print a
    credential blob - reading one needs ``CredReadW`` either way, and going through PowerShell
    would mean compiling C# at runtime via ``Add-Type``: slow, frequently flagged by
    antivirus, and blocked outright by some execution policies. The ``keyring`` package was
    also rejected, since it would rewrite the Linux and macOS paths that are already verified.

    Everything ctypes-related is imported inside this function on purpose: ``ctypes.wintypes``
    raises on non-Windows, so importing it at module scope would break the module everywhere
    else.
    """
    if sys.platform != "win32":
        return None

    import ctypes
    import ctypes.wintypes

    CRED_TYPE_GENERIC = 1

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", ctypes.wintypes.DWORD),
            ("dwHighDateTime", ctypes.wintypes.DWORD),
        ]

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
            ("TargetName", ctypes.wintypes.LPWSTR),
            ("Comment", ctypes.wintypes.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", ctypes.wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", ctypes.wintypes.DWORD),
            ("AttributeCount", ctypes.wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", ctypes.wintypes.LPWSTR),
            ("UserName", ctypes.wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.CredReadW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    advapi32.CredReadW.restype = ctypes.wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    # keytar's target format. Measured on a real install: target=Termius/localKey.
    target = f"{service}/{ACCOUNT}"
    pcred = ctypes.POINTER(CREDENTIAL)()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        return None

    try:
        cred = pcred.contents
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
    finally:
        advapi32.CredFree(pcred)

    value, encoding = _decode_credential_blob(blob)
    if not value:
        return None
    _LAST_BLOB_ENCODING[service] = encoding
    return value


def _available_backends() -> list[tuple[str, object]]:
    backends: list[tuple[str, object]] = []
    if shutil.which("secret-tool"):
        backends.append(("secret-tool", _from_secret_tool))
    if sys.platform == "darwin" and shutil.which("security"):
        backends.append(("macOS keychain", _from_macos_keychain))
    if sys.platform == "win32":
        # advapi32 ships with Windows, so this backend is always available.
        backends.append(("Windows Credential Manager", _from_credential_manager))
    return backends


def find_local_key() -> tuple[str, str]:
    """Return ``(key_base64, source_description)``; raise LocalKeyNotFound if unavailable.

    The two failure modes are reported separately on purpose. "No keyring client installed"
    and "the client works but has no such entry" need completely different fixes, and
    conflating them sends people looking in the wrong place.
    """
    backends = _available_backends()

    if not backends:
        raise LocalKeyNotFound(
            "No OS keyring client found, so the key could not be read automatically.\n"
            "\n"
            "This is a missing tool, not a missing key. Either install a client:\n"
            "  Fedora/RHEL     sudo dnf install libsecret\n"
            "  Debian/Ubuntu   sudo apt install libsecret-tools\n"
            "  Arch            sudo pacman -S libsecret\n"
            "  nix             nix shell nixpkgs#libsecret\n"
            "\n"
            "...or read the key some other way and pass it in:\n"
            "  --local-key-file <file containing the base64 localKey>\n"
            "\n"
            "The key lives under service=termius-app (snap) or service=Termius (macOS),\n"
            f"account={ACCOUNT}. Any keyring browser (Seahorse, KWalletManager) can show it."
        )

    for service in CANDIDATE_SERVICES:
        for backend, fn in backends:
            value = fn(service)
            if value:
                detail = f"{backend} (service={service}, account={ACCOUNT}"
                encoding = _LAST_BLOB_ENCODING.get(service)
                if encoding:
                    detail += f", blob encoding={encoding}"
                return value, detail + ")"

    tried = ", ".join(name for name, _ in backends)
    raise LocalKeyNotFound(
        f"A keyring client is available ({tried}) but it holds no Termius localKey.\n"
        f"Tried service names: {', '.join(CANDIDATE_SERVICES)} with account={ACCOUNT}.\n"
        "\n"
        "Most likely causes:\n"
        "  - Termius has never been launched on this machine (the key is created on first run)\n"
        "  - the keyring is locked; unlock it and retry\n"
        "  - Termius stores it under a service name not in the list above\n"
        "\n"
        "Check by hand:\n"
        "  secret-tool lookup service termius-app account localKey        # Linux\n"
        "  security find-generic-password -s Termius -a localKey -w       # macOS\n"
        "\n"
        "Then pass the value via --local-key-file."
    )


def load_local_key(path: str | None) -> tuple[str, str]:
    """Prefer an explicit file, otherwise fall back to the OS keyring."""
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip(), f"file ({path})"
    return find_local_key()
