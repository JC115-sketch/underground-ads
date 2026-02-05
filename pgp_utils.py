from cryptography.hazmat.primitives import ciphers
import pgpy
from typing import Tuple
from pgpy.constants import (PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm)

def generate_ecc_keypair(name: str, email: str, comment: str = "") -> Tuple[str, str]:
    """Generate ECC PGP keypair"""
    primary = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, 256)
    uid = pgpy.PGPUID.new(name, email=email, comment=comment)

    # UID and preferred algorithms
    primary.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128], compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed])

    enc_subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, 256)
    primary.add_subkey(enc_subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})

    pub_armored = str(primary.pubkey)
    priv_armored = str(primary)

    return pub_armored, priv_armored

def parse_pubkey(pub_armored: str) -> pgpy.PGPKey: # function signature annotation parse_pubkey.__annotations__
    k, _ = pgpy.PGPKey.from_blob(pub_armored) # k is assigned key value, in tuple, _ is discarded
    return k

def parse_privkey(priv_armored: str) -> pgpy.PGPKey:
    k, _ = pgpy.PGPKey.from_blob(priv_armored)
    return k

def encrypt_message_with_pub(pub_armored: str, plaintext: str) -> str:
    pub = parse_pubkey(pub_armored)
    msg = pgpy.PGPMessage.new(plaintext)
    enc = pub.encrypt(msg)
    return str(enc)

def decrypt_message_with_priv(priv_armored: str, passphrase: str, ciphertext_armored: str) -> str:
    priv = parse_privkey(priv_armored)
    # If key is protected unlock here; current code uses an unprotected private key string.
    # add passphrases to PGP keys themselves, you'd do: priv.unlock(passphrase)
    msg = pgpy.PGPMessage.from_blob(ciphertext_armored)
    plain = priv.decrypt(msg)
    # return the literal textual content
    return str(plain.message)




