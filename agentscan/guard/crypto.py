# agentscan/guard/crypto.py
#
# Hardened cryptographic engine implementing NIST SP 800-38D, NIST SP 800-90A,
# and IETF RFC 8032 / RFC 8452 / RFC 9106.

from __future__ import annotations

import hmac
import secrets

from cryptography.exceptions import InvalidTag  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

AES_256_KEY_BYTES = 32
NONCE_BYTES_AES_GCM_SIV = 12
TAG_BYTES_AES_GCM_SIV = 16
MIN_CIPHERTEXT_BYTES_AES_GCM_SIV = NONCE_BYTES_AES_GCM_SIV + TAG_BYTES_AES_GCM_SIV

ARGON2ID_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2ID_TIME_COST = 3
ARGON2ID_PARALLELISM = 4
ARGON2ID_KEY_LENGTH = 32

DEFAULT_CSPRNG_BYTES = 32


class CryptographicEngine:
    """
    Zero-Trust Cryptographic Primitives conforming to NIST SP 800-38D,
    NIST SP 800-90A, and IETF RFC 8032 / RFC 8452 / RFC 9106.
    """

    @staticmethod
    def generate_csprng_nonce(bytes_len: int = DEFAULT_CSPRNG_BYTES) -> str:
        """
        Generates a cryptographically secure pseudorandom token as a hex string.

        Parameters
        ----------
        bytes_len : Number of random bytes to generate (default 32 for 256 bits).

        Returns
        -------
        Hex-encoded string of the random bytes.
        """
        return secrets.token_hex(bytes_len)

    @staticmethod
    def constant_time_compare(val_a: str, val_b: str) -> bool:
        """
        Constant-time comparison to eliminate timing side-channels (CWE-208).

        Parameters
        ----------
        val_a : First string value.
        val_b : Second string value.

        Returns
        -------
        True if values are identical, False otherwise.
        """
        return hmac.compare_digest(val_a.encode("utf-8"), val_b.encode("utf-8"))

    @staticmethod
    def derive_key_argon2id(passphrase: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit key using Argon2id (RFC 9106).

        Parameters
        ----------
        passphrase : Input secret passphrase to derive key from.
        salt : Cryptographic salt bytes.

        Returns
        -------
        32-byte derived cryptographic key.
        """
        kdf = Argon2id(
            salt=salt,
            length=ARGON2ID_KEY_LENGTH,
            iterations=ARGON2ID_TIME_COST,
            lanes=ARGON2ID_PARALLELISM,
            memory_cost=ARGON2ID_MEMORY_COST_KIB,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def encrypt_aes_gcm_siv(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypts data with AES-256-GCM-SIV (RFC 8452).

        Provides authenticated encryption with nonce-misuse resistance.

        Parameters
        ----------
        plaintext : Raw bytes to encrypt.
        key : 32-byte AES-256 key.
        associated_data : Optional authenticated additional data (AAD).

        Returns
        -------
        Combined payload containing 12-byte nonce followed by ciphertext and authentication tag.

        Raises
        ------
        ValueError : If key is not exactly 32 bytes.
        """
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(
                f"AES-256 requires a {AES_256_KEY_BYTES}-byte key, got {len(key)} bytes."
            )

        nonce = secrets.token_bytes(NONCE_BYTES_AES_GCM_SIV)
        aesgcm_siv = AESGCMSIV(key)
        ciphertext = aesgcm_siv.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    @staticmethod
    def decrypt_aes_gcm_siv(payload: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypts data encrypted with AES-256-GCM-SIV.

        Parameters
        ----------
        payload : Encrypted payload (12-byte nonce prepended to ciphertext + tag).
        key : 32-byte AES-256 key.
        associated_data : Optional authenticated additional data (AAD).

        Returns
        -------
        Decrypted plaintext bytes.

        Raises
        ------
        ValueError : If payload length is insufficient or key length is invalid.
        InvalidTag : If ciphertext or associated data has been tampered with.
        """
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(
                f"AES-256 requires a {AES_256_KEY_BYTES}-byte key, got {len(key)} bytes."
            )
        if len(payload) < MIN_CIPHERTEXT_BYTES_AES_GCM_SIV:
            raise ValueError(
                f"Invalid ciphertext length: expected at least {MIN_CIPHERTEXT_BYTES_AES_GCM_SIV} bytes, got {len(payload)}."
            )

        nonce = payload[:NONCE_BYTES_AES_GCM_SIV]
        ciphertext = payload[NONCE_BYTES_AES_GCM_SIV:]
        aesgcm_siv = AESGCMSIV(key)
        return aesgcm_siv.decrypt(nonce, ciphertext, associated_data)
