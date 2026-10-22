"""PEM parsing, validation and fingerprinting for the aztecKey RSA public key.

The official mKKM client serves the key from Firebase Remote Config as a
PKCS#1 PEM (``-----BEGIN RSA PUBLIC KEY-----``); a rotation could switch to
a SubjectPublicKeyInfo PEM (``-----BEGIN PUBLIC KEY-----``), so both shapes
are accepted — mirroring ``parseRsaPublicKey`` in mobile_kkm's ekp_crypto.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PEM_BODY_RE = re.compile(r"-----BEGIN (RSA PUBLIC KEY|PUBLIC KEY)-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)-----END \1-----")

MIN_KEY_BITS = 2048


class InvalidKeyError(ValueError):
    """The PEM is not a usable RSA public key."""


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """One validated key snapshot as served by the API."""

    pem: str
    fingerprint: str
    # When this key was first seen upstream.
    fetched_at: datetime
    # When upstream last confirmed it (fetch or 304).
    last_checked_at: datetime
    version: int

    def age_seconds(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        return max(0, int((now - self.fetched_at).total_seconds()))


def _pem_body(pem: str) -> str:
    """Extracts and normalizes the base64 body from either PEM envelope."""
    match = _PEM_BODY_RE.search(pem)
    if not match:
        raise InvalidKeyError("no PEM block found")
    body = re.sub(r"\s+", "", match.group("body"))
    return body


def parse_public_key(pem: str) -> rsa.RSAPublicKey:
    """Parses and validates an RSA public key from a PKCS#1 or SPKI PEM."""
    body = _pem_body(pem)
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyError(f"invalid base64 in PEM body: {exc}") from exc

    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(f"unparseable public key: {exc}") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidKeyError(f"not an RSA key: {type(key).__name__}")
    if key.key_size < MIN_KEY_BITS:
        raise InvalidKeyError(f"RSA key too small: {key.key_size} bits (< {MIN_KEY_BITS})")
    return key


def fingerprint(key: rsa.RSAPublicKey) -> str:
    """Stable SHA-256 fingerprint over the key's SPKI (DER) encoding."""
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def validate_aztec_key(pem: str) -> tuple[rsa.RSAPublicKey, str]:
    """Validates a fetched Remote Config `aztecKey` value.

    Returns the parsed key and its fingerprint; raises [InvalidKeyError]
    otherwise. Never raises for any other reason.
    """
    key = parse_public_key(pem)
    return key, fingerprint(key)
