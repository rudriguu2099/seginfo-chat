import os

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from test.test_ecdh import Z_AB


salt = os.urandom(16)

key_A2B = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    info=b"A2B",
).derive(Z_AB)

key_B2A = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    info=b"B2A",
).derive(Z_AB)