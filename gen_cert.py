import datetime
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography import x509
from cryptography.x509.oid import NameOID


def gerar():

    # chave RSA do servidor (>= 2048 bits conforme o TP pede)
    sk_server = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pk_server = sk_server.public_key()

    nome = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"tp3-chat-server"),
    ])

    agora = datetime.datetime.now(datetime.timezone.utc)

    # certificado autoassinado: emissor == titular (é o servidor "assinando a si mesmo")
    cert = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(pk_server)
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + datetime.timedelta(days=365))
        .sign(sk_server, hashes.SHA256())
    )

    os.makedirs("certs", exist_ok=True)

    with open("certs/server_key.pem", "wb") as f:
        f.write(
            sk_server.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption(),
            )
        )

    with open("certs/server_cert.pem", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    print("Gerado: server_key.pem (privado, fica só no servidor)")
    print("Gerado: server_cert.pem (público, copie para os clientes)")


if __name__ == "__main__":
    gerar()
