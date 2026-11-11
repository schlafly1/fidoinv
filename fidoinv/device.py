"""Finding FIDO HID devices and reading their getInfo data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, CredentialManagement
from fido2.hid import CtapHidDevice

from . import aaguids
from .errors import FidoInvError, access_denied_hint, is_access_denied, no_device_hint


def list_devices() -> list[CtapHidDevice]:
    try:
        return list(CtapHidDevice.list_devices())
    except Exception as e:  # pragma: no cover - platform dependent
        if is_access_denied(e):
            raise FidoInvError(access_denied_hint(e)) from e
        raise


def select_device(index: int | None) -> tuple[int, CtapHidDevice]:
    devs = list_devices()
    if not devs:
        raise FidoInvError(no_device_hint())
    if index is None:
        if len(devs) > 1:
            lines = ["More than one FIDO device is connected; pick one with --device N:"]
            lines += [f"  {i}: {describe_usb(d)}" for i, d in enumerate(devs)]
            raise FidoInvError("\n".join(lines))
        return 0, devs[0]
    if not 0 <= index < len(devs):
        raise FidoInvError(f"--device {index} is out of range; run 'fidoinv list' (0..{len(devs) - 1}).")
    return index, devs[index]


def _desc(dev: Any):
    return getattr(dev, "descriptor", None)


def usb_fields(dev: Any) -> dict[str, str]:
    d = _desc(dev)
    vid = getattr(d, "vid", None)
    pid = getattr(d, "pid", None)
    return {
        "product_name": str(getattr(d, "product_name", None) or getattr(dev, "product_name", "") or ""),
        "usb_vid": f"{vid:04x}" if isinstance(vid, int) else "",
        "usb_pid": f"{pid:04x}" if isinstance(pid, int) else "",
        "usb_serial": str(getattr(d, "serial_number", None) or getattr(dev, "serial_number", "") or ""),
        "path": str(getattr(d, "path", "") or ""),
    }


def describe_usb(dev: Any) -> str:
    u = usb_fields(dev)
    s = f"{u['product_name'] or '(unnamed)'}  [{u['usb_vid']}:{u['usb_pid']}]"
    if u["usb_serial"]:
        s += f"  serial {u['usb_serial']}"
    return s


def open_ctap2(dev: Any) -> Ctap2 | None:
    """Return a Ctap2 session, or None if the device only speaks U2F/CTAP1."""
    try:
        return Ctap2(dev)
    except ValueError:
        return None
    except Exception as e:
        if is_access_denied(e):
            raise FidoInvError(access_denied_hint(e)) from e
        raise


@dataclass
class DeviceInfo:
    usb: dict[str, str]
    ctap2: bool
    aaguid: str = ""
    model: str = ""
    versions: list[str] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    firmware_version: Any = None
    max_creds_in_list: Any = None
    max_cred_id_length: Any = None
    remaining_disc_creds: Any = None
    min_pin_length: Any = None
    pin_uv_protocols: list[int] = field(default_factory=list)
    algorithms: list[Any] = field(default_factory=list)
    transports: list[str] = field(default_factory=list)
    certifications: Any = None
    pin_retries: Any = None
    uv_retries: Any = None
    cred_mgmt: bool = False
    device_version: str = ""

    @property
    def pin_set(self) -> bool:
        return bool(self.options.get("clientPin"))

    def as_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["pin_set"] = self.pin_set
        return d


def read_info(dev: Any, ctap: Ctap2 | None = None) -> DeviceInfo:
    if ctap is None:
        ctap = open_ctap2(dev)
    dv = getattr(dev, "device_version", None)
    di = DeviceInfo(usb=usb_fields(dev), ctap2=ctap is not None,
                    device_version=".".join(str(x) for x in dv) if isinstance(dv, tuple) else str(dv or ""))
    if ctap is None:
        return di
    info = ctap.info
    di.aaguid = str(info.aaguid)
    di.model = aaguids.lookup(di.aaguid)
    di.versions = list(info.versions or [])
    di.extensions = list(info.extensions or [])
    di.options = dict(info.options or {})
    di.firmware_version = info.firmware_version
    di.max_creds_in_list = info.max_creds_in_list
    di.max_cred_id_length = info.max_cred_id_length
    di.remaining_disc_creds = info.remaining_disc_creds
    di.min_pin_length = info.min_pin_length
    di.pin_uv_protocols = list(info.pin_uv_protocols or [])
    di.algorithms = [a.get("alg") if isinstance(a, dict) else a for a in (info.algorithms or [])]
    di.transports = list(info.transports or [])
    di.certifications = info.certifications
    di.cred_mgmt = CredentialManagement.is_supported(info)
    if di.pin_set:
        try:
            cp = ClientPin(ctap)
            di.pin_retries = cp.get_pin_retries()[0]
            if di.options.get("uv") is not None:
                try:
                    di.uv_retries = cp.get_uv_retries()
                except CtapError:
                    pass
        except (CtapError, ValueError):
            pass
    return di
