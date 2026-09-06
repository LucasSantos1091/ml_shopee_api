class ShopeeError(Exception):
    """Erro base para os clientes da Shopee."""


class ShopeeAuthError(ShopeeError):
    pass


class ShopeeAPIError(ShopeeError):
    def __init__(self, status_code: int, payload: dict | str) -> None:
        self.status_code = status_code
        self.payload = payload
        super().__init__(f"Shopee API error {status_code}: {payload}")
