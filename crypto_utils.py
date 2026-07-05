"""
Funções compartilhadas por cliente e servidor.

Mantidas num módulo à parte por um motivo de segurança prático:
cliente e servidor PRECISAM calcular o hash H e usar os mesmos
parâmetros de PSS/HKDF, senão a verificação nunca bate. Duplicar
esse código em dois arquivos é receita pra um dessincronizar do
outro.
"""

import hashlib
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Autenticação do servidor (RSA-PSS)
# ---------------------------------------------------------------------------

def calcular_H(pk_server_der: bytes, pk_client_raw: bytes,
                client_id: str, salt: bytes) -> bytes:
    """
    H = SHA256(pk_server || pk_client || client_id || salt)

    pk_server_der : bytes DER (SubjectPublicKeyInfo) da chave RSA do servidor
    pk_client_raw : 32 bytes raw da chave pública X25519 do cliente
    client_id     : string UUID do cliente (convertida para 16 bytes binários)
    salt          : 16 bytes gerados pelo servidor nesse handshake
    """
    client_id_bytes = uuid.UUID(client_id).bytes  # 16 bytes, conforme o spec

    material = pk_server_der + pk_client_raw + client_id_bytes + salt

    return hashlib.sha256(material).digest()


def assinar(sk_server, H: bytes) -> bytes:
    """Assina H com RSA-PSS(SHA256). Só o servidor chama isso."""
    return sk_server.sign(
        H,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )


def verificar_assinatura(pk_server, H: bytes, assinatura: bytes) -> bool:
    """
    Verifica a assinatura RSA-PSS. Retorna True/False em vez de deixar
    a exceção estourar, porque no cliente queremos tratar "assinatura
    inválida" como um evento normal de segurança (possível MITM), não
    como um bug.
    """
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


# ---------------------------------------------------------------------------
# Derivação de chaves E2E (HKDF) por par de clientes
# ---------------------------------------------------------------------------

def derivar_chave(shared_secret: bytes, salt_par: bytes, label: bytes) -> bytes:
    """
    PRK = HKDF-Extract(salt_par, shared_secret)   (feito internamente)
    K   = HKDF-Expand(PRK, info=label, L=16)

    Chamar essa função duas vezes com labels diferentes (b"A2B" e b"B2A")
    e o MESMO (shared_secret, salt_par) produz as duas chaves de direção,
    porque o PRK interno é o mesmo -- só o expand muda.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,           # AES-128
        salt=salt_par,
        info=label,
    ).derive(shared_secret)


def papel_na_conversa(meu_id: str, peer_id: str):
    """
    Decide deterministicamente, sem nenhuma troca extra de mensagens,
    quem usa o label 'A2B' pra ENVIAR e quem usa pra RECEBER.
    Regra: o client_id menor (ordem de string) é sempre "A".

    Retorna (label_envio, label_recebimento).
    """
    if meu_id < peer_id:
        return b"A2B", b"B2A"
    else:
        return b"B2A", b"A2B"
