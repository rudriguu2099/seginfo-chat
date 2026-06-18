import uuid

sender_id = uuid.uuid4().bytes
recipient_id = uuid.uuid4().bytes

seq_no = 1
seq_bytes = seq_no.to_bytes(8, "big")

nonce = b"123456789012"

ciphertext = b"mensagem_cifrada"

frame = (
    nonce
    + sender_id
    + recipient_id
    + seq_bytes
    + ciphertext
)

print(len(frame))