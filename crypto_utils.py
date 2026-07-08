import hashlib
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



def calcular_H(pk_server_der: bytes, pk_client_raw: bytes, client_id: str, salt: bytes) -> bytes:

    #calcula o hash h (reapriveitado tp3)
    client_id_bytes = uuid.UUID(client_id).bytes  # 16 bytes, conforme o spec

    material = pk_server_der + pk_client_raw + client_id_bytes + salt

    return hashlib.sha256(material).digest()


def assinar(sk_server, H: bytes) -> bytes:
    #Assina H com RSA-PSS(SHA256). Função so do servidor
    return sk_server.sign(
        H,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )


def verificar_assinatura(pk_server, H: bytes, assinatura: bytes) -> bool:
    #Verifica a assinatura RSA. Retorna True/False
    try:
        pk_server.verify(
            assinatura,
            H,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False



def derivar_chave(shared_secret: bytes, salt_par: bytes, label: bytes) -> bytes:
    # Derivação de chaves E2E (HKDF) por par de clientes
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,           # objeto AES
        salt=salt_par,
        info=label,
    ).derive(shared_secret)


def papel_na_conversa(meu_id: str, peer_id: str):
    #qm tem o client id menor (em questão de ordem de string) é sempre o "A", so pra organizar a comunicação
    if meu_id < peer_id:
        return b"A2B", b"B2A"
    else:
        return b"B2A", b"A2B"
