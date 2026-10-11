# tests/test_enterprise_security_spec.py
#
# Cryptographic primitives verification conforming to NIST SP 800-38D,
# NIST SP 800-90A, and IETF RFC 8032 / RFC 8452 / RFC 9106.

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from agentscan.guard.crypto import CryptographicEngine


def test_csprng_nonce_generation() -> None:
    """Validate 256-bit CSPRNG token generation and uniqueness per NIST SP 800-90A."""
    nonce1 = CryptographicEngine.generate_csprng_nonce(32)
    nonce2 = CryptographicEngine.generate_csprng_nonce(32)

    assert len(nonce1) == 64  # 32 bytes in hex
    assert len(nonce2) == 64
    assert nonce1 != nonce2

    nonce_custom = CryptographicEngine.generate_csprng_nonce(16)
    assert len(nonce_custom) == 32


def test_constant_time_compare() -> None:
    """Validate constant-time comparison against timing side-channels (CWE-208)."""
    secret = "f8a9e2d1c0b3a4f5"
    identical = "f8a9e2d1c0b3a4f5"
    different = "f8a9e2d1c0b3a4f6"
    prefix = "f8a9e2d1c0b3"

    assert CryptographicEngine.constant_time_compare(secret, identical) is True
    assert CryptographicEngine.constant_time_compare(secret, different) is False
    assert CryptographicEngine.constant_time_compare(secret, prefix) is False
    assert CryptographicEngine.constant_time_compare("", "") is True
    assert CryptographicEngine.constant_time_compare(secret, "") is False


def test_argon2id_key_derivation() -> None:
    """Validate Argon2id (RFC 9106) key derivation parameters and determinism."""
    passphrase = "enterprise-master-passphrase-2026"
    salt = os.urandom(16)

    key1 = CryptographicEngine.derive_key_argon2id(passphrase, salt)
    key2 = CryptographicEngine.derive_key_argon2id(passphrase, salt)

    assert len(key1) == 32
    assert key1 == key2

    diff_salt = os.urandom(16)
    key3 = CryptographicEngine.derive_key_argon2id(passphrase, diff_salt)
    assert key1 != key3

    diff_pass = "different-passphrase"
    key4 = CryptographicEngine.derive_key_argon2id(diff_pass, salt)
    assert key1 != key4


def test_aes_gcm_siv_roundtrip_and_tampering() -> None:
    """Validate AES-256-GCM-SIV (RFC 8452) authenticated encryption and misuse resistance."""
    key = os.urandom(32)
    plaintext = b"agent-secret-credentials-top-secret"
    aad = b"tenant-id-enterprise-001"

    encrypted = CryptographicEngine.encrypt_aes_gcm_siv(plaintext, key, associated_data=aad)
    assert len(encrypted) >= 12 + 16 + len(plaintext)

    decrypted = CryptographicEngine.decrypt_aes_gcm_siv(encrypted, key, associated_data=aad)
    assert decrypted == plaintext

    # Tampering with ciphertext tag must fail
    tampered_body = bytearray(encrypted)
    tampered_body[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        CryptographicEngine.decrypt_aes_gcm_siv(bytes(tampered_body), key, associated_data=aad)

    # Tampering with associated data must fail
    with pytest.raises(InvalidTag):
        CryptographicEngine.decrypt_aes_gcm_siv(encrypted, key, associated_data=b"wrong-aad")

    # Invalid key length must raise ValueError
    with pytest.raises(ValueError, match="32-byte key"):
        CryptographicEngine.encrypt_aes_gcm_siv(plaintext, b"short-key")

    with pytest.raises(ValueError, match="32-byte key"):
        CryptographicEngine.decrypt_aes_gcm_siv(encrypted, b"short-key", associated_data=aad)

    # Truncated ciphertext payload must raise ValueError
    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        CryptographicEngine.decrypt_aes_gcm_siv(b"short", key)
