"""Tests for aztec_key_relay.keys — PEM validation and fingerprinting."""

from __future__ import annotations

import pytest
from conftest import REAL_AZTEC_KEY_PEM, generate_pkcs1_pem
from cryptography.hazmat.primitives import serialization

from aztec_key_relay.keys import InvalidKeyError, fingerprint, parse_public_key, validate_aztec_key


def test_parses_real_deployed_key() -> None:
    key = parse_public_key(REAL_AZTEC_KEY_PEM)
    assert key.key_size == 2048
    fp = fingerprint(key)
    assert len(fp) == 64
    # Fingerprint is stable across calls (deterministic SPKI encoding).
    assert fingerprint(parse_public_key(REAL_AZTEC_KEY_PEM)) == fp


def test_parses_spki_envelope() -> None:
    """A rotation could switch to SubjectPublicKeyInfo — must be accepted."""
    pem = generate_pkcs1_pem()
    key = parse_public_key(pem)
    spki = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    parsed = parse_public_key(spki)
    assert fingerprint(parsed) == fingerprint(key)


def test_rejects_garbage() -> None:
    with pytest.raises(InvalidKeyError, match="PEM"):
        parse_public_key("not a pem at all")


def test_rejects_truncated_body() -> None:
    with pytest.raises(InvalidKeyError):
        parse_public_key("-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA\n-----END RSA PUBLIC KEY-----")


def test_rejects_non_rsa_key() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    spki = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(InvalidKeyError, match="not an RSA key"):
        parse_public_key(spki)


def test_rejects_weak_key() -> None:
    with pytest.raises(InvalidKeyError, match="too small"):
        parse_public_key(generate_pkcs1_pem(bits=1024))


def test_validate_aztec_key_returns_key_and_fingerprint() -> None:
    key, fp = validate_aztec_key(REAL_AZTEC_KEY_PEM)
    assert key.key_size == 2048
    assert fp == fingerprint(key)
