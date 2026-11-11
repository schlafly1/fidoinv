import csv
import json

import pytest

from fidoinv import cli, creds, device, coseutil, csvout, totp
from tests import fakes


@pytest.fixture
def env(monkeypatch):
    state = {"devs": [fakes.FakeDev()], "info": fakes.make_info()}
    monkeypatch.setattr(device, "list_devices", lambda: state["devs"])
    monkeypatch.setattr(device, "Ctap2", lambda dev: fakes.FakeCtap2(state["info"]))
    monkeypatch.setattr(device, "ClientPin", fakes.FakeClientPin)
    monkeypatch.setattr(creds, "ClientPin", fakes.FakeClientPin)
    monkeypatch.setattr(creds, "CredentialManagement", fakes.FakeCredMan)
    fakes.FakeCredMan.store = fakes.sample_store()
    fakes.FakeCredMan.deleted = []
    fakes.FakeClientPin.retries = 8
    fakes.FakeClientPin.calls = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": fakes.FakeClientPin.good_pin)
    return state


def read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_list(env, capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "0: YubiKey OTP+FIDO+CCID  [1050:0407]" in out
    assert "YubiKey 5 Series" in out


def test_list_no_devices(env, capsys):
    env["devs"] = []
    assert cli.main(["list"]) == 2
    assert "No FIDO device found" in capsys.readouterr().err


def test_info_text_and_json(env, capsys):
    assert cli.main(["info"]) == 0
    out = capsys.readouterr().out
    assert "ee882879-721c-4913-9775-3dfcce97072a" in out
    assert "Remaining passkey slots  98" in out
    assert "Credential management    supported" in out
    assert cli.main(["info", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["pin_retries"] == 8 and d["cred_mgmt"] is True and d["usb"]["usb_vid"] == "1050"


def test_multiple_devices_need_index(env, capsys):
    env["devs"] = [fakes.FakeDev(), fakes.FakeDev(name="Solo 4.1.5", vid=0x0483, pid=0xa2ca)]
    assert cli.main(["info"]) == 2
    assert "--device N" in capsys.readouterr().err
    assert cli.main(["info", "--device", "1"]) == 0
    assert cli.main(["info", "--device", "5"]) == 2


def test_inventory_appends(env, tmp_path, capsys):
    out = tmp_path / "keys.csv"
    assert cli.main(["inventory", "--label", "blue", "--out", str(out)]) == 0
    rows = read(out)
    assert [r["record_type"] for r in rows] == ["device", "passkey", "passkey", "passkey"]
    assert "3 passkey(s) listed" in rows[0]["note"]
    gh = rows[1]
    assert gh["rp_id"] == "github.com" and gh["rp_name"] == "GitHub"
    assert gh["user_name"] == "roger" and gh["user_id"] == "0102"
    assert coseutil.b64url_decode(gh["credential_id"]) == b"cred-gh-1"
    assert gh["cose_alg"] == "ES256 (-7)" and gh["public_key"].startswith("MFkw")
    assert gh["cred_protect"].startswith("2 ") and gh["large_blob_key"] == "yes"
    assert rows[3]["cose_alg"] == "EdDSA (-8)" and rows[3]["public_key"].startswith("MCow")
    assert fakes.FakeClientPin.calls[-1] is not None  # permission token requested
    # second token appends, header written once
    env["info"] = fakes.make_info(cred_mgmt=False)
    assert cli.main(["inventory", "--label", "old", "--out", str(out)]) == 0
    rows = read(out)
    assert rows[-1]["token_label"] == "old"
    assert rows[-1]["note"] == "credential management not supported"
    assert out.read_text(encoding="utf-8").count("timestamp,token_label") == 1


def test_inventory_preview_credman_uses_no_permissions(env, tmp_path):
    env["info"] = fakes.make_info(preview=True)
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "solo", "-o", str(out)]) == 0
    assert fakes.FakeClientPin.calls[-1] is None
    assert len(read(out)) == 4


def test_inventory_no_pin(env, tmp_path):
    env["info"] = fakes.make_info(pin=False)
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "x", "-o", str(out)]) == 0
    assert "no PIN set" in read(out)[0]["note"]


def test_inventory_wrong_pin(env, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "0000")
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "x", "-o", str(out)]) == 2
    assert "Wrong PIN. 7 attempt(s) left" in capsys.readouterr().err
    assert not out.exists()


def test_inventory_totp_unsupported_brand(env, tmp_path, capsys):
    env["devs"] = [fakes.FakeDev(name="Thetis Key")]
    env["info"] = fakes.make_info(aaguid="1f8e43df-71ff-e11d-bea3-c4ee7003b232")
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "t", "-o", str(out), "--totp"]) == 0
    rows = read(out)
    assert rows[-1]["record_type"] == "totp" and "Thetis Key Manager" in rows[-1]["note"]


def test_inventory_totp_yubikey(env, tmp_path, monkeypatch):
    monkeypatch.setitem(totp.PROVIDERS, "yubikey",
                        lambda: [totp.OtpAccount("GitHub", "roger", "TOTP", "30", "no", "YubiKey OATH")])
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "y", "-o", str(out), "--totp"]) == 0
    r = read(out)[-1]
    assert r["record_type"] == "totp" and r["rp_id"] == "GitHub" and r["user_name"] == "roger"
    assert "period 30s" in r["note"]


def test_delete_requires_yes(env, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda p="": "no")
    assert cli.main(["delete", "--rp", "github.com", "--user", "roger"]) == 1
    assert fakes.FakeCredMan.deleted == []
    monkeypatch.setattr("builtins.input", lambda p="": "yes")
    assert cli.main(["delete", "--rp", "github.com", "--user", "roger"]) == 0
    assert fakes.FakeCredMan.deleted == [b"cred-gh-1"]


def test_delete_by_cred_id_and_flag(env):
    cid = coseutil.b64url(b"cred-gh-2")
    assert cli.main(["delete", "--rp", "GitHub.com", "--cred-id", cid, "--yes"]) == 0
    assert fakes.FakeCredMan.deleted == [b"cred-gh-2"]


def test_delete_needs_selector_and_no_match(env, capsys):
    assert cli.main(["delete", "--rp", "github.com"]) == 2
    assert cli.main(["delete", "--rp", "nope.example", "--user", "x", "--yes"]) == 1
    assert fakes.FakeCredMan.deleted == []


def test_u2f_only_device(env, monkeypatch, tmp_path):
    monkeypatch.setattr(device, "Ctap2", lambda dev: (_ for _ in ()).throw(ValueError("no ctap2")))
    out = tmp_path / "k.csv"
    assert cli.main(["inventory", "-l", "u2f", "-o", str(out)]) == 0
    assert "U2F only" in read(out)[0]["note"]


def test_csv_existing_header_kept(tmp_path):
    p = tmp_path / "k.csv"
    p.write_text("timestamp,token_label,note", encoding="utf-8")  # no trailing newline
    csvout.append_rows(p, [{"timestamp": "t", "token_label": "a", "note": "n", "rp_id": "x"}])
    assert p.read_text(encoding="utf-8").splitlines() == ["timestamp,token_label,note", "t,a,n"]


def test_onlykey_label_parse():
    accts = totp.parse_onlykey_labels("Slot 1a: Google\nSlot 1b:\nSlot 2a: GitHub TOTP\nnoise")
    assert [(a.issuer, a.name) for a in accts] == [("slot 1a", "Google"), ("slot 2a", "GitHub TOTP")]


def test_brand_detection():
    assert totp.brand_of("", "Feitian ePass FIDO2 Authenticator") == "feitian"
    assert totp.brand_of("uTrust FIDO2 Security Key", "") == "utrust"
    assert totp.brand_of("OnlyKey", "") == "onlykey"
    assert totp.brand_of("Mystery", "") == "unknown"


def test_windows_hint(monkeypatch):
    from fidoinv import errors
    monkeypatch.setattr(errors, "is_windows", lambda: True)
    monkeypatch.setattr(errors, "is_windows_admin", lambda: False)
    assert "Administrator" in errors.no_device_hint()
    e = OSError(13, "Permission denied")
    assert errors.is_access_denied(e)


def test_yubikey_oath_listing(monkeypatch):
    import sys
    import types
    from contextlib import contextmanager

    class Cred:
        def __init__(self, issuer, name):
            self.issuer, self.name = issuer, name
            self.oath_type = types.SimpleNamespace(name="TOTP")
            self.period, self.touch_required = 30, False

    class Session:
        locked = True
        validated = None

        def __init__(self, conn):
            pass

        def derive_key(self, pw):
            return b"k:" + pw.encode()

        def validate(self, key):
            Session.validated = key

        def list_credentials(self):
            return [Cred("GitHub", "roger"), Cred(None, "plain")]

    class Dev:
        @contextmanager
        def open_connection(self, t):
            yield object()

    mods = {
        "ykman": types.ModuleType("ykman"),
        "ykman.device": types.SimpleNamespace(list_all_devices=lambda types_: [(Dev(), types.SimpleNamespace(serial=123))]),
        "yubikit": types.ModuleType("yubikit"),
        "yubikit.core": types.ModuleType("yubikit.core"),
        "yubikit.core.smartcard": types.SimpleNamespace(SmartCardConnection=object),
        "yubikit.oath": types.SimpleNamespace(OathSession=Session),
    }
    for k, v in mods.items():
        monkeypatch.setitem(sys.modules, k, v)
    accts = totp.list_yubikey(prompt=lambda p: "pw")
    assert Session.validated == b"k:pw"
    assert [(a.issuer, a.name) for a in accts] == [("GitHub", "roger"), ("", "plain")]
    assert accts[0].source == "YubiKey OATH (serial 123)" and accts[0].touch_required == "no"
