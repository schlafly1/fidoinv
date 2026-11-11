"""Fake CTAP objects so tests run without hardware."""

from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap2 import CredentialManagement
from fido2.webauthn import Aaguid

R = CredentialManagement.RESULT

YUBI_AAGUID = "ee882879-721c-4913-9775-3dfcce97072a"


def ec_cose():
    k = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    return {1: 2, 3: -7, -1: 1, -2: k.x.to_bytes(32, "big"), -3: k.y.to_bytes(32, "big")}


def make_info(cred_mgmt=True, pin=True, aaguid=YUBI_AAGUID, preview=False):
    opts = {"rk": True, "up": True, "clientPin": pin}
    versions = ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]
    if cred_mgmt and not preview:
        opts["credMgmt"] = True
        opts["pinUvAuthToken"] = True
    if cred_mgmt and preview:
        opts["credentialMgmtPreview"] = True
        versions = ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"]
    return SimpleNamespace(
        versions=versions, extensions=["credProtect", "hmac-secret"], aaguid=Aaguid.parse(aaguid),
        options=opts, max_msg_size=1200, pin_uv_protocols=[2, 1], max_creds_in_list=8,
        max_cred_id_length=128, transports=["usb"], algorithms=[{"alg": -7, "type": "public-key"}],
        firmware_version=0x050704, min_pin_length=4, remaining_disc_creds=98, certifications=None,
    )


class FakeCtap2:
    def __init__(self, info):
        self.info = info


class FakeDev:
    def __init__(self, name="YubiKey OTP+FIDO+CCID", vid=0x1050, pid=0x0407, serial=""):
        self.descriptor = SimpleNamespace(path="/dev/hidraw0", vid=vid, pid=pid,
                                          product_name=name, serial_number=serial)
        self.device_version = (5, 7, 4)
        self.closed = False

    def close(self):
        self.closed = True


class FakeClientPin:
    PERMISSION = __import__("fido2.ctap2", fromlist=["ClientPin"]).ClientPin.PERMISSION
    good_pin = "123456"
    retries = 8
    calls = []

    def __init__(self, ctap, protocol=None):
        self.ctap = ctap
        self.protocol = "proto"

    @staticmethod
    def is_token_supported(info):
        return bool(info.options.get("pinUvAuthToken"))

    def get_pin_retries(self):
        return (self.retries, None)

    def get_uv_retries(self):
        return 0

    def get_pin_token(self, pin, permissions=None, permissions_rpid=None):
        from fido2.ctap import CtapError
        FakeClientPin.calls.append(permissions)
        if pin != self.good_pin:
            FakeClientPin.retries -= 1
            raise CtapError(CtapError.ERR.PIN_INVALID)
        return b"token"


class FakeCredMan:
    store = {}
    deleted = []

    def __init__(self, ctap, proto, token):
        self.ctap = ctap

    @staticmethod
    def is_supported(info):
        return CredentialManagement.is_supported(info)

    def get_metadata(self):
        n = sum(len(v["creds"]) for v in self.store.values())
        return {R.EXISTING_CRED_COUNT: n, R.MAX_REMAINING_COUNT: 100 - n}

    def enumerate_rps(self):
        return [{R.RP: v["rp"], R.RP_ID_HASH: h} for h, v in self.store.items()]

    def enumerate_creds(self, rp_hash):
        return list(self.store[rp_hash]["creds"])

    def delete_cred(self, desc):
        FakeCredMan.deleted.append(desc["id"])
        for v in self.store.values():
            v["creds"] = [c for c in v["creds"] if c[R.CREDENTIAL_ID]["id"] != desc["id"]]


def sample_store():
    return {
        b"h1" * 16: {
            "rp": {"id": "github.com", "name": "GitHub"},
            "creds": [
                {R.USER: {"id": b"\x01\x02", "name": "roger", "displayName": "Roger"},
                 R.CREDENTIAL_ID: {"id": b"cred-gh-1", "type": "public-key"},
                 R.PUBLIC_KEY: ec_cose(), R.CRED_PROTECT: 2, R.LARGE_BLOB_KEY: b"x" * 32},
                {R.USER: {"id": b"\x03", "name": "alt", "displayName": "Alt"},
                 R.CREDENTIAL_ID: {"id": b"cred-gh-2", "type": "public-key"},
                 R.PUBLIC_KEY: ec_cose()},
            ],
        },
        b"h2" * 16: {
            "rp": {"id": "google.com"},
            "creds": [
                {R.USER: {"id": b"\xff", "name": "r@example.com", "displayName": "R S"},
                 R.CREDENTIAL_ID: {"id": b"cred-goog", "type": "public-key"},
                 R.PUBLIC_KEY: {1: 1, 3: -8, -1: 6, -2: b"\x11" * 32}},
            ],
        },
    }
