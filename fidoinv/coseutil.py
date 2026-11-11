"""Convert COSE public keys (as returned by credential management) to text."""

from __future__ import annotations

import base64
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

ALG_NAMES = {
    -7: "ES256",
    -8: "EdDSA",
    -35: "ES384",
    -36: "ES512",
    -37: "PS256",
    -47: "ES256K",
    -257: "RS256",
    -19: "Ed25519",
}

_EC_CURVES = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1, 8: ec.SECP256K1}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def alg_label(cose: Mapping[int, Any]) -> str:
    alg = cose.get(3)
    if alg is None:
        return ""
    name = ALG_NAMES.get(alg)
    return f"{name} ({alg})" if name else str(alg)


def _to_crypto_key(cose: Mapping[int, Any]):
    kty = cose.get(1)
    if kty == 2:  # EC2
        curve = _EC_CURVES.get(cose.get(-1))
        if curve is None:
            return None
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve()).public_key()
    if kty == 1:  # OKP
        crv = cose.get(-1)
        if crv == 6:
            return ed25519.Ed25519PublicKey.from_public_bytes(bytes(cose[-2]))
        if crv == 7:
            return ed448.Ed448PublicKey.from_public_bytes(bytes(cose[-2]))
        return None
    if kty == 3:  # RSA
        n = int.from_bytes(cose[-1], "big")
        e = int.from_bytes(cose[-2], "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    return None


def spki_b64(cose: Mapping[int, Any]) -> str:
    """Base64 SubjectPublicKeyInfo DER (the body of a PEM 'PUBLIC KEY'), or ''."""
    try:
        key = _to_crypto_key(cose)
    except Exception:
        return ""
    if key is None:
        return ""
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode("ascii")


def spki_pem(cose: Mapping[int, Any]) -> str:
    body = spki_b64(cose)
    if not body:
        return ""
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def cose_b64url(cose: Mapping[int, Any]) -> str:
    from fido2 import cbor

    return b64url(cbor.encode(dict(cose)))
