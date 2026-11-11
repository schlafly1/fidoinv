"""Friendly error type and platform hints."""

import os
import sys


class FidoInvError(Exception):
    """An error with a message meant for the user (no traceback)."""


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_windows_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


LINUX_UDEV_HINT = (
    "On Linux, your user needs read/write access to the token's /dev/hidraw* node.\n"
    "Install your distro's FIDO udev rules (e.g. the 'libfido2' or 'libu2f-udev' package),\n"
    "or add a rule such as:\n"
    '  KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"\n'
    "to /etc/udev/rules.d/70-fido.rules (use your token's vendor id), then run\n"
    "  sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "and re-insert the token."
)

WINDOWS_ADMIN_HINT = (
    "On Windows, programs other than the browser can only talk to FIDO tokens directly\n"
    "when run as Administrator. Open PowerShell or Command Prompt with\n"
    "'Run as administrator' and try again."
)


def no_device_hint() -> str:
    if is_windows():
        if not is_windows_admin():
            return "No FIDO device found (or access denied).\n" + WINDOWS_ADMIN_HINT
        return "No FIDO device found. Insert a token and try again."
    if sys.platform.startswith("linux"):
        return "No FIDO device found. Insert a token and try again.\n" + LINUX_UDEV_HINT
    return "No FIDO device found. Insert a token and try again."


def access_denied_hint(exc: BaseException) -> str:
    msg = f"Access to the FIDO device was denied ({exc})."
    if is_windows():
        return msg + "\n" + WINDOWS_ADMIN_HINT
    if sys.platform.startswith("linux"):
        return msg + "\n" + LINUX_UDEV_HINT
    return msg


def is_access_denied(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) == 5:
            return True
        if exc.errno in (getattr(os, "EACCES", 13), getattr(os, "EPERM", 1)):
            return True
    return False
