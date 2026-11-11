"""PIN handling and resident-credential enumeration/deletion."""

from __future__ import annotations

import getpass
from dataclasses import dataclass
from typing import Any, Callable

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, CredentialManagement

from . import coseutil
from .errors import FidoInvError

R = CredentialManagement.RESULT

CRED_PROTECT_NAMES = {1: "uvOptional", 2: "uvOptionalWithCredentialIDList", 3: "uvRequired"}


@dataclass
class Credential:
    rp_id: str
    rp_name: str
    rp_id_hash: bytes
    user_id: bytes
    user_name: str
    user_display_name: str
    credential_id: bytes
    cose_key: dict
    cred_protect: Any
    large_blob_key: bool

    @property
    def credential_id_b64(self) -> str:
        return coseutil.b64url(self.credential_id)

    def row(self) -> dict[str, str]:
        cp = self.cred_protect
        return {
            "rp_id": self.rp_id,
            "rp_name": self.rp_name,
            "user_name": self.user_name,
            "user_display_name": self.user_display_name,
            "user_id": self.user_id.hex(),
            "credential_id": self.credential_id_b64,
            "cose_alg": coseutil.alg_label(self.cose_key),
            "public_key": coseutil.spki_b64(self.cose_key),
            "public_key_cose": coseutil.cose_b64url(self.cose_key),
            "cred_protect": (f"{cp} ({CRED_PROTECT_NAMES[cp]})" if cp in CRED_PROTECT_NAMES else ("" if cp is None else str(cp))),
            "large_blob_key": "yes" if self.large_blob_key else "no",
        }


def _pin_error(e: CtapError, ctap: Ctap2) -> FidoInvError:
    code = e.code
    if code == CtapError.ERR.PIN_INVALID:
        try:
            left = ClientPin(ctap).get_pin_retries()[0]
            return FidoInvError(f"Wrong PIN. {left} attempt(s) left before the token locks.")
        except Exception:
            return FidoInvError("Wrong PIN.")
    if code == CtapError.ERR.PIN_BLOCKED:
        return FidoInvError("The PIN is blocked (too many wrong tries). Only a FIDO reset (which erases all passkeys) can recover it.")
    if code == CtapError.ERR.PIN_AUTH_BLOCKED:
        return FidoInvError("Too many wrong PINs this session. Unplug the token, plug it back in, and try again.")
    if code == CtapError.ERR.PIN_NOT_SET:
        return FidoInvError("No PIN is set on this token; set one first (e.g. in your browser's security key settings).")
    if code == CtapError.ERR.PIN_POLICY_VIOLATION:
        return FidoInvError("The PIN does not meet the token's PIN policy.")
    return FidoInvError(f"PIN error from token: {e}")


def open_credman(
    ctap: Ctap2, pin: str | None = None, prompt: Callable[[str], str] = getpass.getpass
) -> CredentialManagement:
    info = ctap.info
    if not CredentialManagement.is_supported(info):
        raise FidoInvError("credential management not supported")
    if not info.options.get("clientPin"):
        raise FidoInvError("No PIN is set on this token; a PIN is required to list passkeys. Set one first (e.g. in your browser's security key settings).")
    if pin is None:
        pin = prompt("FIDO2 PIN: ")
    if not pin:
        raise FidoInvError("No PIN entered.")
    client_pin = ClientPin(ctap)
    perms = ClientPin.PERMISSION.CREDENTIAL_MGMT if ClientPin.is_token_supported(info) else None
    try:
        token = client_pin.get_pin_token(pin, perms)
    except CtapError as e:
        raise _pin_error(e, ctap) from e
    finally:
        pin = None  # drop our reference promptly
    return CredentialManagement(ctap, client_pin.protocol, token)


def metadata(cm: CredentialManagement) -> tuple[Any, Any]:
    try:
        md = cm.get_metadata()
        return md.get(R.EXISTING_CRED_COUNT), md.get(R.MAX_REMAINING_COUNT)
    except CtapError:
        return None, None


def enumerate_all(cm: CredentialManagement) -> list[Credential]:
    out: list[Credential] = []
    for rp in cm.enumerate_rps():
        rp_ent = rp.get(R.RP) or {}
        rp_hash = rp.get(R.RP_ID_HASH)
        for c in cm.enumerate_creds(rp_hash):
            user = c.get(R.USER) or {}
            cid = c.get(R.CREDENTIAL_ID) or {}
            out.append(
                Credential(
                    rp_id=str(rp_ent.get("id", "")),
                    rp_name=str(rp_ent.get("name", "") or ""),
                    rp_id_hash=bytes(rp_hash or b""),
                    user_id=bytes(user.get("id", b"") or b""),
                    user_name=str(user.get("name", "") or ""),
                    user_display_name=str(user.get("displayName", "") or ""),
                    credential_id=bytes(cid.get("id", b"") if isinstance(cid, dict) else cid),
                    cose_key=dict(c.get(R.PUBLIC_KEY) or {}),
                    cred_protect=c.get(R.CRED_PROTECT),
                    large_blob_key=bool(c.get(R.LARGE_BLOB_KEY)),
                )
            )
    return out


def match(creds: list[Credential], rp: str, user: str | None = None, cred_id: str | None = None) -> list[Credential]:
    rp_l = rp.lower()
    res = [c for c in creds if c.rp_id.lower() == rp_l]
    if user is not None:
        res = [c for c in res if user in (c.user_name, c.user_display_name)]
    if cred_id is not None:
        try:
            want = coseutil.b64url_decode(cred_id)
        except Exception as e:
            raise FidoInvError(f"--cred-id is not valid base64url: {e}") from e
        res = [c for c in res if c.credential_id == want]
    return res


def delete(cm: CredentialManagement, cred: Credential) -> None:
    cm.delete_cred({"id": cred.credential_id, "type": "public-key"})
