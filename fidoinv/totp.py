"""Optional TOTP/OATH account-name listing (never secrets, never codes).

Only brands with a documented host protocol are implemented:

* YubiKey   - Yubico OATH applet over smart card (CCID), via ``yubikit``
              (pip install yubikey-manager). Lists issuer/account names.
* OnlyKey   - no OATH listing protocol; ``onlykey-cli getlabels`` returns slot
              labels (which may be passwords, TOTP or other). Used if found on PATH.

Others (Feitian, Thetis, TrustKey, uTrust, Solo) use vendor-specific tools with
no published protocol for listing; they report "not supported".
"""

from __future__ import annotations

import getpass
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass
class OtpAccount:
    issuer: str
    name: str
    oath_type: str = ""
    period: str = ""
    touch_required: str = ""
    source: str = ""

    def row(self) -> dict[str, str]:
        detail = ", ".join(
            x for x in (
                self.oath_type,
                f"period {self.period}s" if self.period else "",
                "touch required" if self.touch_required == "yes" else "",
            ) if x
        )
        return {
            "rp_id": self.issuer,
            "user_name": self.name,
            "note": f"{self.source}" + (f" ({detail})" if detail else ""),
        }


class TotpNotSupported(Exception):
    pass


def brand_of(product_name: str, model: str) -> str:
    s = f"{product_name} {model}".lower()
    for key, brand in (
        ("yubi", "yubikey"),
        ("onlykey", "onlykey"),
        ("solo", "solo"),
        ("thetis", "thetis"),
        ("trustkey", "trustkey"),
        ("utrust", "utrust"),
        ("identiv", "utrust"),
        ("feitian", "feitian"),
        ("epass", "feitian"),
        ("biopass", "feitian"),
    ):
        if key in s:
            return brand
    return "unknown"


VENDOR_TOOL = {
    "feitian": "Feitian's FT Authenticator / SK Manager",
    "thetis": "the Thetis Key Manager (Windows) or Thetis Authenticator app",
    "trustkey": "the TrustKey KeyManager",
    "utrust": "the uTrust Key Manager (NFC+ models only have OATH)",
    "solo": "nothing - Solo v1 has no TOTP/OATH applet",
}


def list_yubikey(prompt: Callable[[str], str] = getpass.getpass) -> list[OtpAccount]:
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.oath import OathSession
    except ImportError as e:
        raise TotpNotSupported(
            "YubiKey OATH listing needs the optional 'yubikey-manager' package: pip install yubikey-manager"
        ) from e
    try:
        devices = list_all_devices([SmartCardConnection])
    except Exception as e:
        raise TotpNotSupported(f"could not reach the YubiKey smart card interface: {e}") from e
    if not devices:
        raise TotpNotSupported("no YubiKey with the smart card (CCID) interface enabled was found")
    if len(devices) > 1:
        raise TotpNotSupported("more than one YubiKey is connected; leave just one plugged in for --totp")
    dev, info = devices[0]
    out: list[OtpAccount] = []
    with dev.open_connection(SmartCardConnection) as conn:
        session = OathSession(conn)
        if session.locked:
            pw = prompt("YubiKey OATH password: ")
            session.validate(session.derive_key(pw))
            pw = None
        for c in session.list_credentials():
            out.append(
                OtpAccount(
                    issuer=c.issuer or "",
                    name=c.name or "",
                    oath_type=getattr(c.oath_type, "name", str(c.oath_type)),
                    period=str(c.period or ""),
                    touch_required="yes" if c.touch_required else ("" if c.touch_required is None else "no"),
                    source=f"YubiKey OATH (serial {info.serial})" if info.serial else "YubiKey OATH",
                )
            )
    return out


_LABEL_RE = re.compile(r"^\s*Slot\s+(\S+)\s*:\s*(.*?)\s*$", re.I)


def parse_onlykey_labels(text: str) -> list[OtpAccount]:
    out = []
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if m and m.group(2):
            out.append(OtpAccount(issuer=f"slot {m.group(1)}", name=m.group(2),
                                  source="OnlyKey slot label (slot may hold a password, TOTP or other)"))
    return out


def list_onlykey() -> list[OtpAccount]:
    exe = shutil.which("onlykey-cli")
    if not exe:
        raise TotpNotSupported(
            "OnlyKey has no OATH listing protocol; install 'onlykey' (pip install onlykey) "
            "so fidoinv can read slot labels with 'onlykey-cli getlabels'"
        )
    try:
        r = subprocess.run([exe, "getlabels"], capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise TotpNotSupported(f"onlykey-cli getlabels failed: {e}") from e
    if r.returncode != 0:
        raise TotpNotSupported(f"onlykey-cli getlabels failed: {(r.stderr or r.stdout).strip()}")
    return parse_onlykey_labels(r.stdout)


PROVIDERS: dict[str, Callable[[], list[OtpAccount]]] = {
    "yubikey": list_yubikey,
    "onlykey": list_onlykey,
}


def list_accounts(brand: str) -> list[OtpAccount]:
    fn = PROVIDERS.get(brand)
    if fn is None:
        tool = VENDOR_TOOL.get(brand)
        hint = f"; use {tool}" if tool else ""
        raise TotpNotSupported(f"TOTP listing is not supported for this token ({brand}){hint}")
    return fn()
