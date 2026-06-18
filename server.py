import asyncio
import json

clients = {}


async def handle_client(reader, writer):

    data = await reader.readline()

    message = json.loads(
        data.decode()
    )

    client_id = message["client_id"]

    public_key = bytes.fromhex(
        message["public_key"]
    )

    clients[client_id] = {
        "writer": writer,
        "public_key": public_key
    }

    print(f"[SERVIDOR] Cliente conectado: {client_id}")
    

    for peer_id, peer in clients.items():

        if peer_id == client_id:
            continue

        # envia A para B

        packet_to_new_client = {
            "type": "peer",
            "client_id": peer_id,
            "public_key": peer["public_key"].hex()
        }

        writer.write(
            (json.dumps(packet_to_new_client) + "\n").encode()
        )

        await writer.drain()

        # envia B para A

        packet_to_existing_client = {
            "type": "peer",
            "client_id": client_id,
            "public_key": public_key.hex()
        }

        peer["writer"].write(
            (json.dumps(packet_to_existing_client) + "\n").encode()
        )

        await peer["writer"].drain()

    while True:

        data = await reader.readline()

        if not data:

            del clients[client_id]

            print()
            print(
                f"[SERVIDOR] Cliente desconectado: {client_id}"
            )
            print()

            break

        packet = json.loads(
            data.decode()
        )

        print("[SERVIDOR] Pacote recebido")
        print("[SERVIDOR] Não possuo a chave AES")
        print("[SERVIDOR] Conteúdo visível:")
        print(packet)
        

        if packet["type"] == "message":

            recipient = packet["recipient"]

            if recipient in clients:

                # TESTE DE TAMPERING / BITFLIP
                
                # ciphertext = packet["ciphertext"]
                
                # ciphertext = (
                #     "0" + ciphertext[1:]
                # )
                
                # packet["ciphertext"] = ciphertext

                print("[SERVIDOR] Encaminhando pacote")
                print(f"Destino: {recipient}")

                clients[recipient]["writer"].write(
                    (json.dumps(packet) + "\n").encode()
                )

                await clients[recipient]["writer"].drain()


async def main():

    server = await asyncio.start_server(
        handle_client,
        "127.0.0.1",
        8888
    )

    
    print("[SERVIDOR] Iniciado")
    

    async with server:
        await server.serve_forever()


asyncio.run(main())