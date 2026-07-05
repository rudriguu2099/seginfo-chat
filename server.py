import asyncio
import json
import os

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
)

from cryptography import x509

import crypto_utils

# ---------------------------------------------------------------------------
# Identidade do servidor (gerada por gen_cert.py)
# ---------------------------------------------------------------------------

with open("certs/server_key.pem", "rb") as f:
    sk_server = load_pem_private_key(f.read(), password=None)

pk_server = sk_server.public_key()

with open("certs/server_cert.pem", "rb") as f:
    server_cert_pem = f.read()

# bytes DER da chave pública do servidor -- usados dentro de H.
# Precisa ser EXATAMENTE a mesma serialização que o cliente vai recalcular
# a partir do certificado, senão H diverge.
pk_server_der = pk_server.public_bytes(
    encoding=Encoding.DER,
    format=PublicFormat.SubjectPublicKeyInfo,
)

# client_id -> {"writer": ..., "public_key": bytes}
clients = {}


async def handle_client(reader, writer):

    # --- 1) Handshake TP3: cliente manda client_id + pk_client -------------
    data = await reader.readline()
    hello = json.loads(data.decode())

    client_id = hello["client_id"]
    public_key = bytes.fromhex(hello["public_key"])

    # --- 2) Servidor prova identidade: gera salt, calcula H, assina --------
    salt_srv = os.urandom(16)

    H = crypto_utils.calcular_H(
        pk_server_der=pk_server_der,
        pk_client_raw=public_key,
        client_id=client_id,
        salt=salt_srv,
    )

    assinatura = crypto_utils.assinar(sk_server, H)

    server_hello = {
        "type": "server_hello",
        "public_key": pk_server_der.hex(),
        "certificate": server_cert_pem.decode(),
        "signature": assinatura.hex(),
        "salt": salt_srv.hex(),
    }

    writer.write((json.dumps(server_hello) + "\n").encode())
    await writer.drain()

    clients[client_id] = {"writer": writer, "public_key": public_key}

    print(f"[SERVIDOR] Cliente autenticado e registrado: {client_id}")

    # --- 3) Broadcast: apresenta o novo cliente a todo mundo já conectado --
    # Para cada par (novo, existente) geramos UM salt de par, e mandamos a
    # MESMA cópia pros dois lados -- é o que permite os dois derivarem a
    # mesma PRK no HKDF (ver crypto_utils.derivar_chave).
    for peer_id, peer in clients.items():

        if peer_id == client_id:
            continue

        salt_par = os.urandom(16)

        # avisa o cliente novo sobre o peer existente
        writer.write((json.dumps({
            "type": "peer",
            "client_id": peer_id,
            "public_key": peer["public_key"].hex(),
            "salt": salt_par.hex(),
        }) + "\n").encode())
        await writer.drain()

        # avisa o peer existente sobre o cliente novo
        peer["writer"].write((json.dumps({
            "type": "peer",
            "client_id": client_id,
            "public_key": public_key.hex(),
            "salt": salt_par.hex(),
        }) + "\n").encode())
        await peer["writer"].drain()

    while True:

        data = await reader.readline()

        if not data:
            del clients[client_id]
            print(f"[SERVIDOR] Cliente desconectado: {client_id}")
            break

        packet = json.loads(data.decode())

        #logs
        print(f"[SERVIDOR] Pacote de {packet.get('sender')} "
              f"para {packet.get('recipient')} (servidor não decifra)")

        if packet["type"] == "message":
            recipient = packet["recipient"]

            # TESTE DE TAMPERING / BITFLIP (descomentar)
            #
            # ciphertext = packet["ciphertext"]
            # packet["ciphertext"] = "0" + ciphertext[1:]

            if recipient in clients:
                clients[recipient]["writer"].write(
                    (json.dumps(packet) + "\n").encode()
                )
                await clients[recipient]["writer"].drain()


async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    print("[SERVIDOR] Iniciado, autenticação RSA-PSS ativa")
    async with server:
        await server.serve_forever()


asyncio.run(main())
