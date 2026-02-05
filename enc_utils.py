import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# params
KDF_ITERATIONS = 200_000
KEY_LEN = 32 # 256 bits
SALT_LEN = 16
NONCE_LEN = 12

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, passphrase: str):
    """Return (ciphertext_b64, salt_b64, nonce_b64)."""
    salt = os.urandom(SALT_LEN)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return base64.b64encode(ct).decode(), base64.b64encode(salt).decode(), base64.b64encode(nonce).decode()

def decrypt_bytes(ciphertext_b64: str, salt_b64: str, nonce_b64: str, passphrase: str) -> bytes:
    ct = base64.b64decode(ciphertext_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt

