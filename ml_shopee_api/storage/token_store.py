"""
Armazenamento local de tokens OAuth, criptografado em repouso.

IMPORTANTE (leia antes de usar em producao):
Este e um armazenamento de referencia para desenvolvimento/uso pessoal em uma
unica maquina. Ele criptografa o conteudo com Fernet (AES-128-CBC + HMAC) e
grava o arquivo com permissao 0600 (somente o dono le/escreve), mas a
seguranca real depende de onde a TOKEN_ENCRYPTION_KEY fica guardada - se ela
estiver no mesmo disco que o arquivo de tokens, um atacante com acesso ao
disco tem as duas metades do segredo.

Para producao, prefira um secrets manager de verdade (AWS Secrets Manager,
GCP Secret Manager, HashiCorp Vault, Azure Key Vault) que separa fisicamente
a chave de criptografia dos dados e oferece rotacao/auditoria - este arquivo
existe apenas para voce ter algo funcional localmente sem inventar seu
proprio esquema de segredo em texto plano.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class TokenStoreError(RuntimeError):
    pass


class SecureTokenStore:
    def __init__(self, path: str | Path, encryption_key: bytes) -> None:
        self._path = Path(path)
        self._fernet = Fernet(encryption_key)

    def save(self, namespace: str, data: dict[str, Any]) -> None:
        """Salva/atualiza os dados de um namespace (ex: 'mercadolivre', 'shopee')."""
        all_data = self._read_all()
        all_data[namespace] = data
        self._write_all(all_data)

    def load(self, namespace: str) -> dict[str, Any] | None:
        return self._read_all().get(namespace)

    def delete(self, namespace: str) -> None:
        all_data = self._read_all()
        all_data.pop(namespace, None)
        self._write_all(all_data)

    # -- internos ------------------------------------------------------

    def _read_all(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        raw = self._path.read_bytes()
        if not raw:
            return {}
        try:
            decrypted = self._fernet.decrypt(raw)
        except InvalidToken as exc:
            raise TokenStoreError(
                "Nao foi possivel descriptografar o arquivo de tokens. "
                "A TOKEN_ENCRYPTION_KEY esta errada ou o arquivo foi corrompido/adulterado."
            ) from exc
        return json.loads(decrypted.decode("utf-8"))

    def _write_all(self, all_data: dict[str, Any]) -> None:
        payload = json.dumps(all_data).encode("utf-8")
        encrypted = self._fernet.encrypt(payload)

        # Escreve em arquivo temporario e faz rename atomico, evitando
        # deixar o arquivo de tokens truncado/corrompido se o processo
        # cair no meio da escrita.
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_path.write_bytes(encrypted)
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600: so o dono le/escreve
        tmp_path.replace(self._path)
