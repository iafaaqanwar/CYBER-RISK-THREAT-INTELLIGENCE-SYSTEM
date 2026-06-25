"""
============================================================
 encryption.py — AES-256-GCM Encryption Module
 Cyber Risk & Threat Intelligence System
============================================================
 Provides authenticated encryption for the Zero Trust
 Secure Log Vault. Uses AES-256 in GCM mode for both
 confidentiality and integrity verification.
============================================================
"""

import os
import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================
# Configuration
# ============================================================
# The encryption key is derived from an environment variable
# or a default passphrase. In production, ALWAYS use env vars.
ENV_KEY_NAME = "CYBER_VAULT_KEY"
DEFAULT_PASSPHRASE = "CyberRisk-ThreatIntel-ZeroTrust-2026"
KEY_LENGTH = 32   # 256 bits for AES-256
SALT_LENGTH = 16  # 128-bit salt for PBKDF2
NONCE_LENGTH = 12 # 96-bit nonce for AES-GCM (recommended)


def _derive_key(passphrase: str = None, salt: bytes = None) -> tuple:
    """
    Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.

    Uses 100,000 iterations of PBKDF2 for key stretching to resist
    brute-force attacks against the passphrase.

    Args:
        passphrase: The secret passphrase string. If None, reads from
                    the CYBER_VAULT_KEY environment variable.
        salt:       Optional salt bytes. Generated randomly if None.

    Returns:
        tuple: (derived_key: bytes, salt: bytes)
    """
    if passphrase is None:
        passphrase = os.environ.get(ENV_KEY_NAME, DEFAULT_PASSPHRASE)

    if salt is None:
        salt = os.urandom(SALT_LENGTH)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=100_000,
    )

    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt


def encrypt_data(plaintext: str, passphrase: str = None) -> dict:
    """
    Encrypts plaintext data using AES-256-GCM authenticated encryption.

    AES-GCM provides both confidentiality (encryption) and integrity
    (authentication tag), ensuring data cannot be tampered with.

    Args:
        plaintext:  The string data to encrypt (typically JSON).
        passphrase: Optional passphrase for key derivation.

    Returns:
        dict with base64-encoded fields:
          - 'ciphertext': The encrypted data
          - 'nonce':      The GCM nonce (needed for decryption)
          - 'salt':       The PBKDF2 salt (needed for key derivation)
          - 'tag':        Included in the GCM ciphertext (last 16 bytes)

    Raises:
        ValueError: If plaintext is empty.
        Exception:  If encryption fails.
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty data.")

    # Derive the encryption key
    key, salt = _derive_key(passphrase)

    # Generate a random nonce for this encryption operation
    nonce = os.urandom(NONCE_LENGTH)

    # Create AES-GCM cipher and encrypt
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode("utf-8")

    # GCM encrypt returns ciphertext + 16-byte auth tag appended
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Encode all binary values as base64 for safe storage
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8"),
    }


def decrypt_data(encrypted_data: dict, passphrase: str = None) -> str:
    """
    Decrypts AES-256-GCM encrypted data and verifies integrity.

    Derives the same key from the stored salt and passphrase,
    then decrypts and authenticates the ciphertext.

    Args:
        encrypted_data: dict with 'ciphertext', 'nonce', 'salt'
                        fields (base64-encoded strings).
        passphrase:     Optional passphrase for key derivation.

    Returns:
        str: The decrypted plaintext string.

    Raises:
        ValueError:           If encrypted_data is missing fields.
        InvalidTag:           If the authentication tag doesn't match
                              (data tampered with).
        Exception:            If decryption fails.
    """
    required_fields = ["ciphertext", "nonce", "salt"]
    for field in required_fields:
        if field not in encrypted_data:
            raise ValueError(f"Missing required field: '{field}'")

    # Decode base64 values
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    salt = base64.b64decode(encrypted_data["salt"])

    # Derive the same key using the stored salt
    key, _ = _derive_key(passphrase, salt=salt)

    # Decrypt and verify authenticity
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext_bytes.decode("utf-8")


def encrypt_dict(data: dict, passphrase: str = None) -> dict:
    """
    Convenience function: serializes a dict to JSON, then encrypts it.

    Args:
        data:       Dictionary to encrypt.
        passphrase: Optional passphrase.

    Returns:
        dict with encrypted fields (ciphertext, nonce, salt).
    """
    json_str = json.dumps(data, default=str)
    return encrypt_data(json_str, passphrase)


def decrypt_dict(encrypted_data: dict, passphrase: str = None) -> dict:
    """
    Convenience function: decrypts data and deserializes from JSON.

    Args:
        encrypted_data: dict with encrypted fields.
        passphrase:     Optional passphrase.

    Returns:
        dict: The decrypted and deserialized dictionary.
    """
    json_str = decrypt_data(encrypted_data, passphrase)
    return json.loads(json_str)


# ============================================================
# Self-Test (run directly to verify encryption works)
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print(" AES-256-GCM Encryption Module — Self-Test")
    print("=" * 50)

    test_data = {
        "threat_type": "ddos",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "risk_level": "critical",
        "mitigation": "Deploy rate limiting and SYN cookies.",
        "timestamp": "2026-06-09T23:00:00",
    }

    print(f"\n[TEST] Original data: {test_data}")

    # Encrypt
    encrypted = encrypt_dict(test_data)
    print(f"\n[TEST] Encrypted ciphertext (truncated): "
          f"{encrypted['ciphertext'][:60]}...")
    print(f"[TEST] Nonce: {encrypted['nonce']}")
    print(f"[TEST] Salt:  {encrypted['salt']}")

    # Decrypt
    decrypted = decrypt_dict(encrypted)
    print(f"\n[TEST] Decrypted data: {decrypted}")

    # Verify
    assert decrypted == test_data, "DECRYPTION MISMATCH!"
    print("\n[PASS] Encryption/Decryption test PASSED ✓")
