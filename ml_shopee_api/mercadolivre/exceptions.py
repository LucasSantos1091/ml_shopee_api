class MLError(Exception):
    """Erro base para o cliente do Mercado Livre."""


class MLAuthError(MLError):
    """Erro no fluxo de autenticacao/autorizacao (OAuth2)."""


class MLAPIError(MLError):
    """Erro retornado pela API do Mercado Livre (status >= 400)."""

    def __init__(self, status_code: int, payload: dict | str) -> None:
        self.status_code = status_code
        self.payload = payload
        super().__init__(f"Mercado Livre API error {status_code}: {payload}")
