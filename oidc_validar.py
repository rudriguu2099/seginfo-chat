from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from keys.google_keys import GOOGLE_CLIENT_ID

_EMISSORES_VALIDOS = ("accounts.google.com", "https://accounts.google.com")


class ErroDeAutenticacao(Exception):
    pass

def validar_id_token(id_token_jwt: str) -> dict:
    try:
        # Isso aqui sozinho já faz: verificar a assinatura via JWKS do
        # Google, checar 'exp' (token não expirado) e checar 'aud', já que o token foi emitido PRA ESSA aplicação, não pra outra.
        claims = google_id_token.verify_oauth2_token(
            id_token_jwt,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
        
    except ValueError as e:
        # assinatura inválida, token expirado, aud errado, JWT malformado...
        raise ErroDeAutenticacao(f"token inválido: {e}")
    
    # Checagens extras 

    # iss: quem emitiu.
    if claims.get("iss") not in _EMISSORES_VALIDOS:
        raise ErroDeAutenticacao(f"issuer inesperado: {claims.get('iss')}")

    # email_verified: Sem essa checagem, alguém poderia se cadastrar
    # com um email que não é dele e o sistema confiaria mesmo assim.
    if not claims.get("email_verified", False):
        raise ErroDeAutenticacao("email não verificado pelo Google")

    # sub: identificador único e IMUTÁVEL do usuário Google. É a chave
    # de identidade real
    if "sub" not in claims:
        raise ErroDeAutenticacao("token sem 'sub'")

    return claims
