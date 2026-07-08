import base64
import hashlib
import os
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs

import requests

from keys.google_keys import GOOGLE_CLIENT_SECRET


AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

REDIRECT_PORT = 8765
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/callback"

def _gerar_pkce():
    # code_verifier: string aleatória de alta entropia (43-128 chars)
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()

    # code_challenge = base64url(SHA256(code_verifier)), sem padding.

    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    return code_verifier, code_challenge


class _CallbackHandler(BaseHTTPRequestHandler):
    # Servidor HTTP local só pra capturar o redirect do Google. O Google não manda o código pra sua aplicação diretamente, 
    # ele manda o NAVEGADOR do usuário redirecionar pra essa URL local como código na query string.
    codigo_recebido = None
    state_recebido = None

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        _CallbackHandler.codigo_recebido = query.get("code", [None])[0]
        _CallbackHandler.state_recebido = query.get("state", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            "<html><body><h3>Login concluído. "
            "Pode voltar pro terminal.</h3></body></html>".encode()
        )

    def log_message(self, *args):
        pass  # silencia o log padrão do http.server


def fazer_login_google(google_client_id: str) -> dict:
    #Executa o fluxo completo e retorna o id_token (JWT) já pronto pra mandar ao servidor.

    code_verifier, code_challenge = _gerar_pkce()

    state = secrets.token_urlsafe(16)

    #na primeira ele manda o code challenge, com o metodo de como gerar o hash dele
    params = {
        "client_id": google_client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }

    url = f"{AUTH_ENDPOINT}?{urlencode(params)}"

    print("[LOGIN] Abrindo o navegador pra você logar com o Google...")
    webbrowser.open(url)

    # sobe um servidor HTTP local, espera UMA requisição, e desliga.
    servidor = HTTPServer(("localhost", REDIRECT_PORT), _CallbackHandler)
    servidor.handle_request()

    codigo = _CallbackHandler.codigo_recebido
    if codigo is None:
        raise RuntimeError("Login cancelado ou falhou (sem 'code' no redirect)")

    if _CallbackHandler.state_recebido != state:
        raise RuntimeError("state não bate -- possível ataque CSRF, abortando")

    # quando for requsititar o token, ele manda o codigo que gerou o hash, com o google verificando e aprovando
    resp = requests.post(TOKEN_ENDPOINT, data={
    "client_id": google_client_id,
    "client_secret": GOOGLE_CLIENT_SECRET,
    "code": codigo,
    "code_verifier": code_verifier,
    "redirect_uri": REDIRECT_URI,
    "grant_type": "authorization_code",
})

    # descomente essas duas linhas pra obter o token jwt e o access token
    # print("STATUS:", resp.status_code)
    # print("RESPOSTA:", resp.text)

    resp.raise_for_status()

    tokens = resp.json()
    return tokens  # contém "id_token", "access_token", etc.
