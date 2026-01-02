import pgpy

from pgpy.constants import (PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm)

def generate_keypair():

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

    uid = pgpy.PGPUID.new("Starry115", email="starry115@example.com", comment="Dev Key 1")

    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications}, hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],)

    return key

def encrypt_message(pubkey_str, plaintext):
    pubkey, _ = pgpy.PGPKey.from_blob(pubkey_str)
    msg = pgpy.PGPMessage.new(plaintext)
    encrypted = pubkey.encrypt(msg)
    return str(encrypted)

def decrypt_message(privkey_str, ciphertext):
    privkey, _ = pgpy.PGPKey.from_blob(privkey_str)
    msg = pgpy.PGPMessage.from_blob(ciphertext)
    decrypted = privkey.decrypt(msg)
    return decrypted.message

