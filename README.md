# Chat E2E com X25519 e AES-GCM

Este projeto consiste em um experimento de comunicação cliente-servidor para simular um serviço de mensageria com criptografia ponta a ponta (End-to-End Encryption - E2E).

A aplicação utiliza conceitos de Segurança da Informação e Criptografia, incluindo:

* Troca de chaves utilizando X25519 (ECDHE);
* Derivação de chaves com HKDF-SHA256;
* Criptografia e autenticação com AES-GCM;
* Nonce aleatório por mensagem;
* Proteção contra ataques de replay utilizando números de sequência (seq_no);
* Servidor atuando apenas como relay/rendezvous, sem acesso ao conteúdo das mensagens.

## Como executar

Atualmente o sistema suporta comunicação entre dois clientes.

1. Inicie o servidor:

```bash
python server.py
```

2. Em dois terminais diferentes, inicie os clientes:

```bash
python client.py
```

3. Após a conexão, os clientes realizarão automaticamente a troca de chaves públicas, o estabelecimento do segredo compartilhado e a derivação das chaves simétricas.

4. As mensagens enviadas pelos clientes serão criptografadas ponta a ponta e encaminhadas pelo servidor, que não possui acesso ao conteúdo em texto puro.

## Observações

* O servidor apenas encaminha mensagens entre os clientes.
* O conteúdo das mensagens trafega criptografado utilizando AES-GCM.
* Mensagens adulteradas são rejeitadas pela verificação de integridade do GCM.
* Mensagens repetidas são descartadas através da validação do número de sequência.
