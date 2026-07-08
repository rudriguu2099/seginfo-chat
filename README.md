# Chat E2E com autenticação Google, TLS 1.3 e X25519 + AES-GCM

Este projeto consiste em um experimento de comunicação cliente-servidor para simular um serviço de mensageria com autenticação de usuário e criptografia ponta a ponta (End-to-End Encryption - E2E).

A aplicação utiliza conceitos de Segurança da Informação e Criptografia, incluindo:

* Autenticação de usuário via **Google (OAuth 2.0 + OIDC)**, com o fluxo Authorization Code + PKCE;
* Validação de identidade via **ID Token (JWT)** emitido pelo Google;
* Canal de transporte protegido com **TLS 1.3**, com certificate pinning do certificado do servidor;
* Autenticação adicional do servidor com assinatura **RSA-PSS**, dentro do túnel TLS;
* Troca de chaves utilizando X25519 (ECDHE);
* Derivação de chaves com HKDF-SHA256;
* Criptografia e autenticação com AES-GCM;
* Nonce aleatório por mensagem;
* Proteção contra ataques de replay utilizando números de sequência (seq_no);
* Servidor atuando apenas como relay/rendezvous, sem acesso ao conteúdo das mensagens.


## Configuração inicial

### 1. Credenciais do Google (OAuth Client)

As credenciais do Google **não ficam hardcoded no código** — elas moram em `keys/google_keys.py`, que é ignorado pelo git (veja `.gitignore`).

1. Crie um OAuth Client do tipo "Desktop app" no [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Crie o arquivo `keys/google_keys.py` com o seguinte conteúdo, substituindo pelos valores do seu client:

```python
GOOGLE_CLIENT_ID = "SEU_CLIENT_ID.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "SEU_CLIENT_SECRET"
```

### 2. Certificado do servidor

```bash
python gen_cert.py
```

Isso gera `certs/server_key.pem` (privado, fica só no servidor) e `certs/server_cert.pem` (público, usado pelo pinning no cliente). Essa pasta também é ignorada pelo git.

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

3. Cada cliente abrirá o navegador para login com o Google (Authorization Code + PKCE). Após autenticado, o servidor valida o `id_token` (OIDC) e libera a conexão.

4. Em seguida, os clientes realizam automaticamente a troca de chaves públicas, o estabelecimento do segredo compartilhado e a derivação das chaves simétricas.

5. As mensagens enviadas pelos clientes serão criptografadas ponta a ponta e encaminhadas pelo servidor, que não possui acesso ao conteúdo em texto puro.

## Observações

* O servidor apenas encaminha mensagens entre os clientes.
* O servidor não vê o `code_verifier` nem o `client_secret` do cliente — só recebe o `id_token` já emitido pelo Google.
* O conteúdo das mensagens trafega criptografado utilizando AES-GCM, dentro de um túnel TLS 1.3.
* Mensagens adulteradas são rejeitadas pela verificação de integridade do GCM.
* Mensagens repetidas são descartadas através da validação do número de sequência.
* Nunca commite `keys/` nem `certs/` — ambas as pastas contêm material sensível e já estão no `.gitignore`.
