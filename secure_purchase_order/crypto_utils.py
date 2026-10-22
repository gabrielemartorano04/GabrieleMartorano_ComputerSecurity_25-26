"""
crypto_utils.py
All cryptographic operations for the Secure Purchase Order System.

Algorithms used:
  - RSA-2048       : key pairs for each role
  - SHA-256        : hashing order payloads
  - RSA-PSS        : digital signatures (signing & verification)
  - AES-256-CBC    : symmetric encryption of payloads
  - RSA-OAEP       : encrypting the AES session key
"""

import os
import base64
import json
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# Key Generation & Serialisation
# ─────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_private_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(key) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )


# ─────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────

def hash_data(data: bytes) -> bytes:
    """SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).digest()


# ─────────────────────────────────────────────
# Digital Signatures  (RSA-PSS / SHA-256)
# ─────────────────────────────────────────────

def sign_data(data: bytes, private_key) -> str:
    """Sign data with RSA-PSS. Returns base64-encoded signature."""
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    """Verify an RSA-PSS signature. Returns True if valid."""
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# AES-256-CBC  (payload encryption)
# ─────────────────────────────────────────────

def _pkcs7_pad(data: bytes, block=16) -> bytes:
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt(plaintext: bytes):
    """
    AES-256-CBC encrypt.
    Returns (ciphertext_bytes, key_bytes, iv_bytes).
    """
    key = os.urandom(32)   # 256-bit session key
    iv  = os.urandom(16)   # 128-bit IV
    padded = _pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return ciphertext, key, iv


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC decrypt."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)


# ─────────────────────────────────────────────
# RSA-OAEP  (session key encryption)
# ─────────────────────────────────────────────

def rsa_encrypt_key(aes_key: bytes, public_key) -> str:
    """RSA-OAEP encrypt the AES session key. Returns base64 string."""
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


def rsa_decrypt_key(encrypted_b64: str, private_key) -> bytes:
    """RSA-OAEP decrypt the AES session key."""
    return private_key.decrypt(
        base64.b64decode(encrypted_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
# High-level message helpers
# ─────────────────────────────────────────────

def build_message(payload: dict, sender_private_key, recipient_public_key) -> dict:
    """
    Full secure message construction:
      1. Serialize payload → JSON bytes (sorted keys for determinism)
      2. SHA-256 hash the payload
      3. RSA-PSS sign the payload with sender's private key
      4. AES-256-CBC encrypt the payload (random key + IV)
      5. RSA-OAEP encrypt the AES key with recipient's public key
    Returns a dict safe to write as JSON.
    """
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    payload_hash  = hash_data(payload_bytes)
    signature     = sign_data(payload_bytes, sender_private_key)
    ciphertext, aes_key, iv = aes_encrypt(payload_bytes)
    encrypted_aes_key = rsa_encrypt_key(aes_key, recipient_public_key)

    return {
        "encrypted_payload": base64.b64encode(ciphertext).decode(),
        "encrypted_aes_key": encrypted_aes_key,
        "iv":                base64.b64encode(iv).decode(),
        "signature":         signature,
        "payload_hash":      base64.b64encode(payload_hash).decode(),
    }


def open_message(message: dict, recipient_private_key, sender_public_key):
    """
    Full secure message decryption & verification:
      1. RSA-OAEP decrypt the AES session key
      2. AES-256-CBC decrypt the payload
      3. Verify SHA-256 hash (tamper detection)
      4. Verify RSA-PSS signature (authentication + non-repudiation)
    Returns (payload_dict, signature_is_valid).
    Raises ValueError if hash check fails (tampering detected).
    """
    aes_key    = rsa_decrypt_key(message["encrypted_aes_key"], recipient_private_key)
    iv         = base64.b64decode(message["iv"])
    ciphertext = base64.b64decode(message["encrypted_payload"])
    payload_bytes = aes_decrypt(ciphertext, aes_key, iv)

    # Integrity check
    computed_hash = hash_data(payload_bytes)
    stored_hash   = base64.b64decode(message["payload_hash"])
    if computed_hash != stored_hash:
        raise ValueError("SHA-256 hash mismatch — payload has been TAMPERED WITH.")

    sig_valid = verify_signature(payload_bytes, message["signature"], sender_public_key)
    payload   = json.loads(payload_bytes.decode())
    return payload, sig_valid
