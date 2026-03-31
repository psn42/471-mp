import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_ecdh_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_bytes

def compute_shared_secret(private_key, peer_public_bytes: bytes) -> bytes:
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)

def derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'simple_tor_key_expansion',
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:16], key_material[16:]

def process_crypto_layer(aes_key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def onion_encrypt(key_iv_pairs: list[tuple[bytes, bytes]], payload: bytes) -> bytes:
    encrypted_payload = payload
    for aes_key, iv in reversed(key_iv_pairs):
        encrypted_payload = process_crypto_layer(aes_key, iv, encrypted_payload)
    return encrypted_payload

def onion_decrypt(aes_key: bytes, iv: bytes, encrypted_payload: bytes) -> bytes:
    return process_crypto_layer(aes_key, iv, encrypted_payload)

def calculate_digest(data: bytes) -> bytes:
    full_hash = hashlib.sha256(data).digest()
    return full_hash[:4]