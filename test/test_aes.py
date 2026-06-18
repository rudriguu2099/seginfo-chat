from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os

key = AESGCM.generate_key(bit_length=128)

aes = AESGCM(key)

nonce = os.urandom(12)

aad = b"metadata"

plaintext = b"Oi mundo"

ciphertext = aes.encrypt(
    nonce,
    plaintext,
    aad
)

result = aes.decrypt(
    nonce,
    ciphertext,
    aad
)

print(result)