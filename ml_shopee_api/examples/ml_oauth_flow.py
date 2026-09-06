"""
Exemplo: fluxo completo de autorizacao OAuth2 do Mercado Livre, rodando um
servidor HTTP local temporario so para capturar o "code" do redirect.

Rode com: python -m examples.ml_oauth_flow (a partir da raiz do projeto)

ATENCAO:
  - O redirect_uri configurado no seu app (developers.mercadolivre.com.br)
    precisa ser IDENTICO ao ML_REDIRECT_URI do seu .env, caractere por
    caractere (inclusive protocolo e porta).
  - Em producao, o redirect_uri deve ser https. Este exemplo usa
    http://localhost apenas porque e o unico jeito pratico de testar em uma
    maquina local sem certificado - nao replique esse padrao em producao.
  - O servidor abaixo so aceita UMA requisicao (o callback) e encerra em
    seguida, para nao deixar uma porta local aberta sem necessidade.
"""
from __future__ import annotations

import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.append(".")

from config import MercadoLivreConfig, token_encryption_key  # noqa: E402
from mercadolivre.auth import MLAuth, generate_pkce_pair, generate_state  # noqa: E402
from storage.token_store import SecureTokenStore  # noqa: E402

_captured: dict[str, str] = {}


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (assinatura exigida pela stdlib)
        qs = parse_qs(urlparse(self.path).query)
        _captured["code"] = qs.get("code", [""])[0]
        _captured["state"] = qs.get("state", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body>Autorizado. Pode fechar esta aba.</body></html>")

    def log_message(self, format: str, *args) -> None:  # silencia log padrao no stdout
        pass


def main() -> None:
    cfg = MercadoLivreConfig.from_env()
    auth = MLAuth(cfg.client_id, cfg.client_secret, cfg.redirect_uri)

    expected_state = generate_state()
    pkce = generate_pkce_pair()
    url = auth.build_authorization_url(expected_state, pkce)

    parsed_redirect = urlparse(cfg.redirect_uri)
    server = HTTPServer((parsed_redirect.hostname, parsed_redirect.port), _CallbackHandler)

    print("Abrindo o navegador para autorizacao...")
    print(f"Se nao abrir automaticamente, acesse: {url}")
    webbrowser.open(url)

    server.handle_request()  # bloqueia ate o callback chegar, depois encerra
    server.server_close()

    if not _captured.get("code"):
        raise SystemExit("Nao recebi o 'code' de autorizacao. Verifique o redirect_uri e tente novamente.")

    # Validacao do 'state' e OBRIGATORIA - protege contra CSRF no fluxo OAuth.
    if _captured.get("state") != expected_state:
        raise SystemExit("state divergente - possivel tentativa de CSRF. Abortando.")

    token_set = auth.exchange_code(_captured["code"], pkce.verifier)

    store = SecureTokenStore("tokens.enc", token_encryption_key())
    store.save("mercadolivre", token_set.to_dict())
    print("Tokens obtidos e salvos (criptografados) em tokens.enc.")


if __name__ == "__main__":
    main()
