import asyncio
import json
import uuid
import os

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives import hashes


# salt fixo
GLOBAL_SALT = b"SALT_PROFESSOR-MICHEL-SALES"

# tabela dos peers conhecidos
# guarda chaves e estado da comunicação
peers = {}

# contador de mensagens enviadas
seq = 0


async def receive_loop(reader, sk_client):

    while True:

        data = await reader.readline()

        if not data:
            break

        packet = json.loads(data.decode())

        if packet["type"] == "peer":

            peer_id = packet["client_id"]

            peer_public_key = X25519PublicKey.from_public_bytes(
                bytes.fromhex(
                    packet["public_key"]
                )
            )

            # ECDH (diffie hellman de curvas elipticas)
            # ska + pkb = secret_ab
            shared_secret = sk_client.exchange(
                peer_public_key
            )

            # transforma o shared secret bruto em uma chave AES pronta para uso
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=GLOBAL_SALT,
                info=b"chat-key"
            ).derive(shared_secret)

            # objeto responsável por criptografar e descriptografar mensagens
            aes = AESGCM(aes_key)

            # guarda tudo que sabemos sobre esse peer
            peers[peer_id] = {
                "public_key": peer_public_key,
                "aes_key": aes_key,
                "aes": aes,
                "last_seq": 0
            }

            print(f"[CLIENTE] Peer registrado: {peer_id}")

        elif packet["type"] == "message":

            seq_no = packet["seq_no"]

            nonce = bytes.fromhex(
                packet["nonce"]
            )

            ciphertext = bytes.fromhex(
                packet["ciphertext"]
            )

            peer_id = next(iter(peers))

            last_seq = peers[peer_id]["last_seq"]

            # proteção contra replay
            if seq_no <= last_seq:

                print("[CLIENTE] Replay detectado")

                continue

            aes = peers[peer_id]["aes"]

            try:

                plaintext = aes.decrypt(
                    nonce,
                    ciphertext,
                    None
                )

            except Exception:

                print("[CLIENTE] Falha de integridade")
                print("[CLIENTE] Mensagem adulterada")

                continue

            peers[peer_id]["last_seq"] = seq_no
            print()
            print("[CLIENTE] Mensagem recebida:")
            print(plaintext.decode())


async def send_loop(writer):

    global seq

    while True:

        msg = await asyncio.to_thread(
            input,
            "Mensagem: "
        )

        if not peers:
            print("Nenhum peer conectado")
            continue

        peer_id = next(iter(peers))

        peer = peers[peer_id]

        aes = peer["aes"]

        plaintext = msg.encode()

        nonce = os.urandom(12)

        
        ciphertext = aes.encrypt(
            nonce,
            plaintext,
            None
        )

        # cada mensagem recebe um número único pra impedir replay
        seq += 1

        # TESTE DE REPLAY
        # descomentar pra forçar seq repetido
        #
        # if seq == 0:
        #     seq = 1
        # else:
        #     seq = 1

        packet = {
            "type": "message",
            "recipient": peer_id,
            "seq_no": seq,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

        writer.write(
            (json.dumps(packet) + "\n").encode()
        )

        await writer.drain()

async def main():

    reader, writer = await asyncio.open_connection(
        "127.0.0.1",
        8888
    )

    client_id = str(uuid.uuid4())

    sk_client = X25519PrivateKey.generate()

    pk_client = sk_client.public_key()

    pk_bytes = pk_client.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    packet = {
        "client_id": client_id,
        "public_key": pk_bytes.hex()
    }

    writer.write(
        (json.dumps(packet) + "\n").encode()
    )

    await writer.drain()

    print("[CLIENTE] Conectado")
    print(client_id)

    asyncio.create_task(
        receive_loop(reader, sk_client)
    )

    asyncio.create_task(
        send_loop(writer)
    )

    while True:
        await asyncio.sleep(1)


asyncio.run(main())