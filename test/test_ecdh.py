#testando dif hellman pra derivação de chaves

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)


sk_A = X25519PrivateKey.generate()
pk_A = sk_A.public_key()


sk_B = X25519PrivateKey.generate()
pk_B = sk_B.public_key()


Z_AB = sk_A.exchange(pk_B)

Z_BA = sk_B.exchange(pk_A)

print(Z_AB.hex())
print(Z_BA.hex())

print(Z_AB == Z_BA)