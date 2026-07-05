import asyncio
import json
import uuid
import os

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

import crypto_utils


# Certificado do servidor, pinado localmente (copiado manualmente da
# máquina do servidor -- é isso que impede um MITM de te enganar com
# um certificado forjado).
with open("certs/server_cert.pem", "rb") as f:
    cert_pinado = x509.load_pem_x509_certificate(f.read())

pk_server_pinado = cert_pinado.public_key()
pk_server_der_pinado = pk_server_pinado.public_bytes(
    encoding=Encoding.DER,
    format=PublicFormat.SubjectPublicKeyInfo,
)

servidor_autenticado = False

# client_id -> {public_key, key_send, key_recv, seq_send, seq_recv,
#               iv_base_send, iv_base_recv}
peers = {}


def registrar_peer(meu_id, peer_id, peer_public_key_bytes, salt, sk_client):
    """
    Deriva as duas chaves de direção + os dois IV base para o par
    (meu_id, peer_id), a partir do segredo ECDH e do salt de par
    que o servidor gerou e mandou pros dois lados.
    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

    # Z_AB = ECDH(sk_A, pk_B) -- o segredo nunca trafega na rede
    shared_secret = sk_client.exchange(peer_public_key)

    label_envio, label_recebimento = crypto_utils.papel_na_conversa(meu_id, peer_id)

    key_send = crypto_utils.derivar_chave(shared_secret, salt, label_envio)
    key_recv = crypto_utils.derivar_chave(shared_secret, salt, label_recebimento)

    # IV base por direção: derivado, não sorteado e transmitido à parte,
    # pra não precisar de mais uma mensagem de handshake. Como cada par
    # (shared_secret, salt) é único, os IV base também são únicos por par.
    iv_base_send = crypto_utils.derivar_chave(
        shared_secret, salt, label_envio + b"-iv"
    )[:4]
    iv_base_recv = crypto_utils.derivar_chave(
        shared_secret, salt, label_recebimento + b"-iv"
    )[:4]

    peers[peer_id] = {
        "public_key": peer_public_key,
        "key_send": key_send,
        "key_recv": key_recv,
        "seq_send": 0,
        "seq_recv": -1,
        "iv_base_send": iv_base_send,
        "iv_base_recv": iv_base_recv,
    }

    print(f"[CLIENTE] Chaves E2E derivadas para peer {peer_id}")


async def receive_loop(reader, sk_client, meu_id):

    global servidor_autenticado

    while True:

        data = await reader.readline()
        if not data:
            break

        packet = json.loads(data.decode())

        # --------------------------------------------------------------
        # Autenticação do servidor (uma vez, logo no início da conexão)
        # --------------------------------------------------------------
        if packet["type"] == "server_hello":

            cert_recebido = packet["certificate"].encode()

            # Pinning: o certificado recebido tem que ser BYTE A BYTE
            # igual ao que já confiamos. Isso é mais forte que validar
            # uma cadeia de CA (que não existe aqui, é autoassinado).
            cert_recebido_obj = x509.load_pem_x509_certificate(cert_recebido)
            if cert_recebido_obj.public_bytes(Encoding.DER) != \
                    cert_pinado.public_bytes(Encoding.DER):
                print("[CLIENTE] ALERTA: certificado do servidor não bate "
                      "com o certificado pinado. Possível MITM. Abortando.")
                return

            salt_srv = bytes.fromhex(packet["salt"])
            assinatura = bytes.fromhex(packet["signature"])

            pk_client_raw = sk_client.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )

            H = crypto_utils.calcular_H(
                pk_server_der=pk_server_der_pinado,
                pk_client_raw=pk_client_raw,
                client_id=meu_id,
                salt=salt_srv,
            )

            ok = crypto_utils.verificar_assinatura(pk_server_pinado, H, assinatura)

            if not ok:
                print("[CLIENTE] ALERTA: assinatura do servidor inválida. "
                      "Abortando conexão.")
                return

            servidor_autenticado = True
            print("[CLIENTE] Servidor autenticado com sucesso (RSA-PSS OK)")

        # --------------------------------------------------------------
        # Novo peer anunciado pelo servidor (broadcast)
        # --------------------------------------------------------------
        elif packet["type"] == "peer":

            if not servidor_autenticado:
                print("[CLIENTE] Ignorando peer: servidor ainda não autenticado")
                continue

            peer_id = packet["client_id"]
            peer_public_key_bytes = bytes.fromhex(packet["public_key"])
            salt = bytes.fromhex(packet["salt"])

            registrar_peer(meu_id, peer_id, peer_public_key_bytes, salt, sk_client)

        # --------------------------------------------------------------
        # Mensagem E2E de algum peer
        # --------------------------------------------------------------
        elif packet["type"] == "message":

            sender_id = packet["sender"]
            recipient_id = packet["recipient"]
            seq_no = packet["seq_no"]
            ciphertext = bytes.fromhex(packet["ciphertext"])

            if recipient_id != meu_id:
                # não deveria acontecer (o servidor roteia por client_id),
                # mas checar de novo aqui custa nada e é defesa em profundidade
                continue

            peer = peers.get(sender_id)
            if peer is None:
                print(f"[CLIENTE] Mensagem de peer desconhecido {sender_id}, ignorando")
                continue

            if seq_no <= peer["seq_recv"]:
                print("[CLIENTE] Replay detectado, descartando")
                continue

            # Nonce e AAD são RECALCULADOS localmente, nunca confiamos
            # apenas no que veio no pacote -- se o valor usado na cifragem
            # não bater exatamente com isso, a tag do GCM falha.
            nonce = peer["iv_base_recv"] + seq_no.to_bytes(8, "big")
            aad = (
                uuid.UUID(sender_id).bytes
                + uuid.UUID(recipient_id).bytes
                + seq_no.to_bytes(8, "big")
            )

            aes = AESGCM(peer["key_recv"])

            try:
                plaintext = aes.decrypt(nonce, ciphertext, aad)
            except Exception:
                print("[CLIENTE] Falha de integridade: mensagem adulterada")
                continue

            peer["seq_recv"] = seq_no
            print(f"\n[CLIENTE] Mensagem de {sender_id[:8]}: {plaintext.decode()}")


async def escolher_destinatario():
    ids = list(peers.keys())
    print("\nPeers conhecidos:")
    for i, pid in enumerate(ids):
        print(f"  [{i}] {pid}")
    escolha = await asyncio.to_thread(input, "Destino (número): ")
    try:
        return ids[int(escolha)]
    except (ValueError, IndexError):
        print("Escolha inválida")
        return None


async def send_loop(writer, meu_id):

    while True:

        if not peers:
            await asyncio.sleep(1)
            continue

        peer_id = await escolher_destinatario()
        if peer_id is None:
            continue

        msg = await asyncio.to_thread(input, "Mensagem: ")

        peer = peers[peer_id]

        peer["seq_send"] += 1
        seq_no = peer["seq_send"]

        # TESTE DE REPLAY -- descomente para forçar o reenvio do mesmo
        # seq_no e demonstrar que o destinatário rejeita (seq_no <= seq_recv).
        #
        # seq_no = 1

        nonce = peer["iv_base_send"] + seq_no.to_bytes(8, "big")
        aad = (
            uuid.UUID(meu_id).bytes
            + uuid.UUID(peer_id).bytes
            + seq_no.to_bytes(8, "big")
        )

        aes = AESGCM(peer["key_send"])
        ciphertext = aes.encrypt(nonce, msg.encode(), aad)

        packet = {
            "type": "message",
            "sender": meu_id,
            "recipient": peer_id,
            "seq_no": seq_no,
            "ciphertext": ciphertext.hex(),
        }

        writer.write((json.dumps(packet) + "\n").encode())
        await writer.drain()


async def main():

    reader, writer = await asyncio.open_connection("127.0.0.1", 8888)

    client_id = str(uuid.uuid4())

    sk_client = X25519PrivateKey.generate()
    pk_client = sk_client.public_key()
    pk_bytes = pk_client.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    writer.write((json.dumps({
        "client_id": client_id,
        "public_key": pk_bytes.hex(),
    }) + "\n").encode())
    await writer.drain()

    print("[CLIENTE] Conectado. Meu client_id:", client_id)

    asyncio.create_task(receive_loop(reader, sk_client, client_id))
    asyncio.create_task(send_loop(writer, client_id))

    while True:
        await asyncio.sleep(1)


asyncio.run(main())