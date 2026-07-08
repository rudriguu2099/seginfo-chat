import asyncio
import json
import ssl
import uuid

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

import crypto_utils
from google_login import fazer_login_google

# mesmo client_id do Google Cloud Console
from keys.google_keys import GOOGLE_CLIENT_ID


with open("certs/server_cert.pem", "rb") as f:
    cert_pinado_bytes = f.read()

cert_pinado = x509.load_pem_x509_certificate(cert_pinado_bytes)
pk_server_pinado = cert_pinado.public_key()
pk_server_der_pinado = pk_server_pinado.public_bytes(
    encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo,
)

servidor_autenticado = False
peers = {}


def montar_contexto_tls_cliente():
    #contexto de tls e configuração de certificado
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="certs/server_cert.pem")

    # mudar o arquivo apontado aqui para simular que o certificado mudou:
    #ctx.load_verify_locations(cafile="certificado_falso.pem")

    return ctx

#tp3 refatorado
def registrar_peer(meu_id, peer_id, peer_public_key_bytes, salt, sk_client):
    #diffie helman pra gerar o shared secret
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = sk_client.exchange(peer_public_key)

    label_envio, label_recebimento = crypto_utils.papel_na_conversa(meu_id, peer_id)

    key_send = crypto_utils.derivar_chave(shared_secret, salt, label_envio)
    key_recv = crypto_utils.derivar_chave(shared_secret, salt, label_recebimento)
    iv_base_send = crypto_utils.derivar_chave(shared_secret, salt, label_envio + b"-iv")[:4]
    iv_base_recv = crypto_utils.derivar_chave(shared_secret, salt, label_recebimento + b"-iv")[:4]

    peers[peer_id] = {
        "public_key": peer_public_key, "key_send": key_send, "key_recv": key_recv,
        "seq_send": 0, "seq_recv": -1,
        "iv_base_send": iv_base_send, "iv_base_recv": iv_base_recv,
    }
    print(f"[CLIENTE] Chaves E2E derivadas para peer {peer_id}")

#tp3 + refatorações
async def receive_loop(reader, sk_client, meu_id):
    global servidor_autenticado

    while True:
        data = await reader.readline()
        if not data:
            break
        packet = json.loads(data.decode())

        if packet["type"] == "server_hello":
            cert_recebido = x509.load_pem_x509_certificate(packet["certificate"].encode())
            if cert_recebido.public_bytes(Encoding.DER) != cert_pinado.public_bytes(Encoding.DER):
                print("[CLIENTE] ALERTA: certificado não bate com o pinado. Abortando.")
                return

            salt_srv = bytes.fromhex(packet["salt"])
            assinatura = bytes.fromhex(packet["signature"])
            pk_client_raw = sk_client.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            H = crypto_utils.calcular_H(pk_server_der_pinado, pk_client_raw, meu_id, salt_srv)

            if not crypto_utils.verificar_assinatura(pk_server_pinado, H, assinatura):
                print("[CLIENTE] ALERTA: assinatura RSA-PSS inválida. Abortando.")
                return

            servidor_autenticado = True
            print("[CLIENTE] Servidor autenticado (RSA-PSS OK, dentro do túnel TLS)")

        elif packet["type"] == "peer":
            if not servidor_autenticado:
                continue
            registrar_peer(
                meu_id, packet["client_id"],
                bytes.fromhex(packet["public_key"]), bytes.fromhex(packet["salt"]),
                sk_client,
            )

        elif packet["type"] == "message":
            sender_id = packet["sender"]
            recipient_id = packet["recipient"]
            seq_no = packet["seq_no"]
            ciphertext = bytes.fromhex(packet["ciphertext"])

            if recipient_id != meu_id:
                continue
            peer = peers.get(sender_id)
            if peer is None or seq_no <= peer["seq_recv"]:
                continue

            nonce = peer["iv_base_recv"] + seq_no.to_bytes(8, "big")
            aad = uuid.UUID(sender_id).bytes + uuid.UUID(recipient_id).bytes + seq_no.to_bytes(8, "big")

            try:
                plaintext = AESGCM(peer["key_recv"]).decrypt(nonce, ciphertext, aad)
            except Exception:
                print("[CLIENTE] Falha de integridade: mensagem adulterada")
                continue

            peer["seq_recv"] = seq_no
            print(f"\n[CLIENTE] Mensagem de {sender_id[:8]}: {plaintext.decode()}")

#adicionado para escolher pra qm mandar mensagem
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

#send loop igual o tp3
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
        nonce = peer["iv_base_send"] + seq_no.to_bytes(8, "big")

        aad = uuid.UUID(meu_id).bytes + uuid.UUID(peer_id).bytes + seq_no.to_bytes(8, "big")
        ciphertext = AESGCM(peer["key_send"]).encrypt(nonce, msg.encode(), aad)
        packet = {
            "type": "message", "sender": meu_id, "recipient": peer_id,
            "seq_no": seq_no, "ciphertext": ciphertext.hex(),
        }
        writer.write((json.dumps(packet) + "\n").encode())
        await writer.drain()


async def main():

    ctx = montar_contexto_tls_cliente()

    # server_hostname é obrigatório pro handshake TLS mesmo com
    # check_hostname=False -- é só um rótulo pro SNI, não afeta a
    # validação (que já é feita via o cert pinado).
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", 8888, ssl=ctx, server_hostname="localhost",
    )
    print("[CLIENTE] Túnel TLS 1.3 estabelecido")

    #login Google ANTES de qualquer coisa do TP3 (ir pra google_login.py)
    tokens = fazer_login_google(GOOGLE_CLIENT_ID)

    id_token = tokens["id_token"]

    #linha pra gerar erro de aldulteramento de jwt
    # id_token = id_token + "adulterado"

    writer.write((json.dumps({"type": "auth", "id_token": id_token}) + "\n").encode())
    await writer.drain()

    resposta = json.loads((await reader.readline()).decode())
    if resposta["type"] != "auth_ok":
        print(f"[CLIENTE] Autenticação rejeitada: {resposta.get('motivo')}")
        return

    print(f"[CLIENTE] Autenticado como {resposta['email']}")

    # Daqui pra baixo é o handshake TP3, sem mudança nenhuma
    client_id = str(uuid.uuid4())
    sk_client = X25519PrivateKey.generate()
    pk_bytes = sk_client.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    writer.write((json.dumps({"client_id": client_id, "public_key": pk_bytes.hex()}) + "\n").encode())
    await writer.drain()

    print("[CLIENTE] Meu client_id:", client_id)

    asyncio.create_task(receive_loop(reader, sk_client, client_id))
    asyncio.create_task(send_loop(writer, client_id))

    while True:
        await asyncio.sleep(1)


asyncio.run(main())