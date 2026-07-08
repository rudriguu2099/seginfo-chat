import asyncio
import json
import os
import ssl

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
)

import crypto_utils
from oidc_validar import validar_id_token, ErroDeAutenticacao


with open("certs/server_key.pem", "rb") as f:
    sk_server = load_pem_private_key(f.read(), password=None)

pk_server = sk_server.public_key()

with open("certs/server_cert.pem", "rb") as f:
    server_cert_pem = f.read()

pk_server_der = pk_server.public_bytes(
    encoding=Encoding.DER,
    format=PublicFormat.SubjectPublicKeyInfo,
)

clients = {}


def montar_contexto_tls():
    #monta o contexto tls pro servidor e assina o certificado com sk 
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile="certs/server_cert.pem", keyfile="certs/server_key.pem")
    return ctx


async def handle_client(reader, writer):

    # TP4: autenticação do usuário via Google antes de qualquer coisa do protocolo TP3 acontecer.
    data = await reader.readline()

    if not data:
        print("Cliente desconectou antes da autenticação")
        writer.close()
        await writer.wait_closed()
        return

    #recebe uma auth message
    auth_msg = json.loads(data.decode())

    if auth_msg.get("type") != "auth":
        writer.write((json.dumps({"type": "auth_fail", "motivo": "esperava auth"}) + "\n").encode())
        await writer.drain()
        writer.close()
        return

    try:
        #essa auth message vai tentar validar o id token pra conseguir os metadados dele e logar ele (oicd)
        claims = validar_id_token(auth_msg["id_token"])
    except ErroDeAutenticacao as e:
        print(f"[SERVIDOR] Login Google rejeitado: {e}")
        writer.write((json.dumps({"type": "auth_fail", "motivo": str(e)}) + "\n").encode())
        await writer.drain()
        writer.close()
        return

    google_sub = claims["sub"]
    email = claims.get("email")

    print(f"[SERVIDOR] Usuário autenticado via Google: {email} (sub={google_sub})")

    writer.write((json.dumps({"type": "auth_ok", "email": email}) + "\n").encode())
    await writer.drain()


    # igual handshake TP3, sem nenhuma mudança na lógica, só q agora roda dentro do túnel TLS que o asyncio já abriu por baixo.
    data = await reader.readline()
    hello = json.loads(data.decode())

    client_id = hello["client_id"]
    public_key = bytes.fromhex(hello["public_key"])

    salt_srv = os.urandom(16)

    H = crypto_utils.calcular_H(
        pk_server_der=pk_server_der,
        pk_client_raw=public_key,
        client_id=client_id,
        salt=salt_srv,
    )
    assinatura = crypto_utils.assinar(sk_server, H)

    writer.write((json.dumps({
        "type": "server_hello",
        "public_key": pk_server_der.hex(),
        "certificate": server_cert_pem.decode(),
        "signature": assinatura.hex(),
        "salt": salt_srv.hex(),
    }) + "\n").encode())
    await writer.drain()

    # tem que guardar a identidade Google junto da sessão é isso que dá rastreabilidade real
    clients[client_id] = {
        "writer": writer,
        "public_key": public_key,
        "google_sub": google_sub,
        "email": email,
    }

    print(f"[SERVIDOR] Cliente registrado: {client_id} ({email})")

    for peer_id, peer in clients.items():
        if peer_id == client_id:
            continue

        salt_par = os.urandom(16)

        writer.write((json.dumps({
            "type": "peer", "client_id": peer_id,
            "public_key": peer["public_key"].hex(), "salt": salt_par.hex(),
        }) + "\n").encode())
        await writer.drain()

        peer["writer"].write((json.dumps({
            "type": "peer", "client_id": client_id,
            "public_key": public_key.hex(), "salt": salt_par.hex(),
        }) + "\n").encode())
        await peer["writer"].drain()

    while True:
        data = await reader.readline()
        if not data:
            del clients[client_id]
            print(f"[SERVIDOR] Cliente desconectado: {client_id}")
            break

        packet = json.loads(data.decode())
        print(f"[SERVIDOR] Pacote de {packet.get('sender')} "
              f"para {packet.get('recipient')} (servidor não decifra)")

        if packet["type"] == "message":
            recipient = packet["recipient"]
            if recipient in clients:
                clients[recipient]["writer"].write((json.dumps(packet) + "\n").encode())
                await clients[recipient]["writer"].drain()


async def main():
    #executnado tudo, monta o tls, e depois liga o servidor em broadcast com contexto tls
    ctx = montar_contexto_tls()
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888, ssl=ctx)
    print("[SERVIDOR] Iniciado com TLS 1.3 + autenticação Google")
    async with server:
        await server.serve_forever()


asyncio.run(main())
