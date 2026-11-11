"""Command line interface for fidoinv."""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from fido2.ctap import CtapError

from . import __version__, aaguids, creds, csvout, device, totp
from .errors import FidoInvError, access_denied_hint, is_access_denied, no_device_hint


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _close(dev: Any) -> None:
    try:
        dev.close()
    except Exception:
        pass


# ---------------------------------------------------------------- list
def cmd_list(args: argparse.Namespace) -> int:
    devs = device.list_devices()
    if not devs:
        raise FidoInvError(no_device_hint())
    for i, d in enumerate(devs):
        line = f"{i}: {device.describe_usb(d)}"
        try:
            ctap = device.open_ctap2(d)
            if ctap is None:
                line += "  (U2F only, no CTAP2)"
            else:
                aag = str(ctap.info.aaguid)
                line += f"  AAGUID {aag}"
                model = aaguids.lookup(aag)
                if model:
                    line += f"  ({model})"
        except FidoInvError:
            raise
        except Exception as e:  # keep listing the others
            line += f"  (error reading info: {e})"
        print(line)
        _close(d)
    return 0


# ---------------------------------------------------------------- info
def _fmt(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v) if v else "-"
    if isinstance(v, dict):
        return ", ".join(f"{k}={'yes' if x is True else 'no' if x is False else x}" for k, x in v.items()) or "-"
    return "-" if v is None or v == "" else str(v)


def cmd_info(args: argparse.Namespace) -> int:
    idx, dev = device.select_device(args.device)
    try:
        di = device.read_info(dev)
    finally:
        _close(dev)
    if args.json:
        d = di.as_dict()
        d["device_index"] = idx
        print(json.dumps(d, indent=2, default=str))
        return 0
    u = di.usb
    rows = [
        ("Device", f"{idx}: {u['product_name']}"),
        ("USB vendor:product", f"{u['usb_vid']}:{u['usb_pid']}"),
        ("USB serial", u["usb_serial"]),
        ("CTAPHID device version", di.device_version),
    ]
    if not di.ctap2:
        rows.append(("CTAP2", "not supported (U2F only); nothing more to read"))
    else:
        rows += [
            ("AAGUID", di.aaguid),
            ("Model", di.model or "(unknown; try 'fidoinv update-aaguids')"),
            ("Versions", _fmt(di.versions)),
            ("Firmware version", _fmt(di.firmware_version)),
            ("Extensions", _fmt(di.extensions)),
            ("Options", _fmt(di.options)),
            ("PIN set", "yes" if di.pin_set else "no"),
            ("PIN retries left", _fmt(di.pin_retries)),
            ("UV retries left", _fmt(di.uv_retries)),
            ("Min PIN length", _fmt(di.min_pin_length)),
            ("PIN/UV protocols", _fmt(di.pin_uv_protocols)),
            ("Algorithms", _fmt(di.algorithms)),
            ("Transports", _fmt(di.transports)),
            ("Max creds in list", _fmt(di.max_creds_in_list)),
            ("Max cred ID length", _fmt(di.max_cred_id_length)),
            ("Remaining passkey slots", _fmt(di.remaining_disc_creds)),
            ("Certifications", _fmt(di.certifications)),
            ("Credential management", "supported" if di.cred_mgmt else "not supported"),
        ]
    w = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{w}}  {v if v not in ('', None) else '-'}")
    return 0


# ---------------------------------------------------------------- inventory
def _base_row(ts: str, label: str, di: device.DeviceInfo) -> dict[str, str]:
    return {
        "timestamp": ts,
        "token_label": label,
        "product_name": di.usb.get("product_name", ""),
        "model": di.model,
        "aaguid": di.aaguid,
        "usb_serial": di.usb.get("usb_serial", ""),
    }


def cmd_inventory(args: argparse.Namespace) -> int:
    idx, dev = device.select_device(args.device)
    ts = _now()
    out = Path(args.out)
    rows: list[dict[str, str]] = []
    try:
        ctap = device.open_ctap2(dev)
        di = device.read_info(dev, ctap)
        base = _base_row(ts, args.label, di)
        note = ""
        if ctap is None:
            note = "CTAP2 not supported (U2F only); credential management not supported"
        elif not di.cred_mgmt:
            note = "credential management not supported"
        elif not di.pin_set:
            note = "no PIN set; a PIN is required to list passkeys"
        else:
            cm = creds.open_credman(ctap, prompt=getpass.getpass)
            existing, remaining = creds.metadata(cm)
            found = creds.enumerate_all(cm)
            note = f"{len(found)} passkey(s) listed"
            if existing is not None:
                note += f"; token reports {existing} stored"
            if remaining is not None:
                note += f", {remaining} slot(s) free"
            for c in found:
                r = dict(base, record_type="passkey")
                r.update(c.row())
                rows.append(r)
        rows.insert(0, dict(base, record_type="device", note=note))
    finally:
        _close(dev)

    if args.totp:
        brand = totp.brand_of(di.usb.get("product_name", ""), di.model)
        try:
            accts = totp.list_accounts(brand)
            for a in accts:
                r = dict(base, record_type="totp")
                r.update(a.row())
                rows.append(r)
            print(f"TOTP: {len(accts)} account name(s) found.")
        except totp.TotpNotSupported as e:
            print(f"TOTP: {e}", file=sys.stderr)
            rows.append(dict(base, record_type="totp", note=f"TOTP not listed: {e}"))
        except Exception as e:
            print(f"TOTP: failed: {e}", file=sys.stderr)
            rows.append(dict(base, record_type="totp", note=f"TOTP listing failed: {e}"))

    n = csvout.append_rows(out, rows)
    print(f"{args.label}: {rows[0]['note']}")
    print(f"Appended {n} row(s) to {out}")
    return 0


# ---------------------------------------------------------------- delete
def cmd_delete(args: argparse.Namespace) -> int:
    if args.user is None and args.cred_id is None and not args.all_for_rp:
        raise FidoInvError("Give --user NAME or --cred-id ID (or --all-for-rp to delete every passkey for that site).")
    idx, dev = device.select_device(args.device)
    try:
        ctap = device.open_ctap2(dev)
        if ctap is None:
            raise FidoInvError("This token does not support CTAP2, so it has no deletable passkeys.")
        cm = creds.open_credman(ctap, prompt=getpass.getpass)
        found = creds.match(creds.enumerate_all(cm), args.rp, args.user, args.cred_id)
        if not found:
            print(f"No passkeys on this token match rp={args.rp!r}"
                  + (f" user={args.user!r}" if args.user else "")
                  + (f" cred-id={args.cred_id}" if args.cred_id else ""))
            return 1
        print(f"{len(found)} matching passkey(s):")
        for c in found:
            print(f"  {c.rp_id}  user={c.user_name!r} display={c.user_display_name!r}  id={c.credential_id_b64}")
        if not args.yes:
            ans = input("Type 'yes' to permanently delete them from the token: ")
            if ans.strip() != "yes":
                print("Cancelled; nothing deleted.")
                return 1
        for c in found:
            creds.delete(cm, c)
            print(f"Deleted {c.rp_id} {c.user_name!r}")
        print("Note: the site still has this passkey on file; remove it there too.")
    finally:
        _close(dev)
    return 0


# ---------------------------------------------------------------- update-aaguids
def cmd_update_aaguids(args: argparse.Namespace) -> int:
    try:
        path, n = aaguids.update()
    except Exception as e:
        raise FidoInvError(f"Download failed: {e}") from e
    print(f"Saved {n} AAGUID names to {path}")
    return 0


# ---------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fidoinv", description="Inventory FIDO2 security keys.")
    p.add_argument("--version", action="version", version=f"fidoinv {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def dev_opt(sp):
        sp.add_argument("--device", "-d", type=int, metavar="N",
                        help="device index from 'fidoinv list' (needed when several are plugged in)")

    sp = sub.add_parser("list", help="show connected FIDO devices")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("info", help="show a token's getInfo data and USB details")
    dev_opt(sp)
    sp.add_argument("--json", action="store_true", help="print JSON")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("inventory", help="append a token's passkeys to a CSV file (asks for the PIN)")
    dev_opt(sp)
    sp.add_argument("--label", "-l", required=True, help="your name for this token, e.g. 'yubikey-blue'")
    sp.add_argument("--out", "-o", default="keys.csv", help="CSV file to append to (default keys.csv)")
    sp.add_argument("--totp", action="store_true",
                    help="also list TOTP/OATH account names (no secrets) where supported")
    sp.set_defaults(func=cmd_inventory)

    sp = sub.add_parser("delete", help="delete passkey(s) from a token (asks for the PIN and confirmation)")
    dev_opt(sp)
    sp.add_argument("--rp", required=True, help="site / relying party id, e.g. github.com")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--user", help="match the user name or display name exactly")
    g.add_argument("--cred-id", help="match the base64url credential id (from the CSV)")
    g.add_argument("--all-for-rp", action="store_true", help="delete every passkey for --rp")
    sp.add_argument("--yes", "-y", action="store_true", help="skip the typed confirmation")
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("update-aaguids", help="download the community AAGUID -> model name list")
    sp.set_defaults(func=cmd_update_aaguids)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FidoInvError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except CtapError as e:
        print(f"Error: the token returned {e}", file=sys.stderr)
        return 2
    except OSError as e:
        if is_access_denied(e):
            print(f"Error: {access_denied_hint(e)}", file=sys.stderr)
            return 2
        raise
