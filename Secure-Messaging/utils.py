#!/usr/bin/env python3
import socket, argparse, json, getpass, random, base64, os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

'''
this file holds functions that are utilized between both client and server
'''

# Derive a 256-bit key from K_client
def derive_key(K_server):
    # Convert K_client to bytes
    K_server_bytes = K_server.to_bytes((K_server.bit_length() + 7) // 8, byteorder="big")
    # Derive a key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info = b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(K_server_bytes)

#encrypt with the key
def encrypt_with_key(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Return nonce concatenated with ciphertext

# Function to decrypt data with AES-GCM
def decrypt_with_key(key, encrypted_data_with_nonce, nonce):
    if nonce:
        aesgcm = AESGCM(key)
        nonce, ciphertext = encrypted_data_with_nonce[:12], encrypted_data_with_nonce[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    else:
        aesgcm = AESGCM(key)
        nonce, ciphertext = encrypted_data_with_nonce[:12], encrypted_data_with_nonce[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)