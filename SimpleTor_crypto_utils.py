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

def derive_tor_keys(shared_secret: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=72,
        salt=None,
        info=b'tor-prototype-key-expansion',
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    fwd_digest_key = key_material[0:20]
    bwd_digest_key = key_material[20:40]
    fwd_aes_key = key_material[40:56]
    bwd_aes_key = key_material[56:72]
    return fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key

def create_client_ciphers(fwd_aes_key: bytes, bwd_aes_key: bytes):
    zero_iv = b'\x00' * 16
    fwd_cipher = Cipher(algorithms.AES(fwd_aes_key), modes.CTR(zero_iv), backend=default_backend()).encryptor()
    bwd_cipher = Cipher(algorithms.AES(bwd_aes_key), modes.CTR(zero_iv), backend=default_backend()).decryptor()
    return fwd_cipher, bwd_cipher

def create_relay_ciphers(fwd_aes_key: bytes, bwd_aes_key: bytes):
    zero_iv = b'\x00' * 16
    fwd_cipher = Cipher(algorithms.AES(fwd_aes_key), modes.CTR(zero_iv), backend=default_backend()).decryptor()
    bwd_cipher = Cipher(algorithms.AES(bwd_aes_key), modes.CTR(zero_iv), backend=default_backend()).encryptor()
    return fwd_cipher, bwd_cipher

def create_running_digests():
    fwd_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    bwd_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    return fwd_digest, bwd_digest