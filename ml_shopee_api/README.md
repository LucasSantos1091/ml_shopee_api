# Cliente Python — Mercado Livre + Shopee

Estrutura de cliente Python para as APIs oficiais do Mercado Livre e da
Shopee, seguindo o fluxo de autenticação de cada uma. Escopo importante:
**as duas APIs só dão acesso aos dados da sua própria conta/loja** — nenhuma
delas expõe um "ranking de mais vendidos do mercado" de forma aberta (isso já
foi discutido antes de este código ser escrito). A exceção parcial é a
Shopee Affiliate API (`shopee/affiliate.py`), que permite buscar ofertas
ordenadas por volume de vendas, mas exige aprovação separada no programa de
afiliados.

## Estrutura

```
ml_shopee_api/
├── config.py                  # carrega .env, valida variáveis obrigatórias
├── mercadolivre/
│   ├── auth.py                 # OAuth2 + PKCE, refresh (token de uso único)
│   ├── client.py                # busca de itens, item, trends, categorias
│   └── exceptions.py
├── shopee/
│   ├── auth.py                  # assinatura HMAC-SHA256, token/refresh
│   ├── client.py                 # endpoints de loja (Open Platform API)
│   ├── affiliate.py               # Affiliate API (GraphQL) — opcional
│   └── exceptions.py
├── storage/
│   └── token_store.py           # tokens salvos criptografados em disco
└── examples/
    ├── ml_oauth_flow.py          # fluxo completo de autorização ML
    ├── ml_search_example.py
    ├── shopee_shop_products_example.py
    └── shopee_affiliate_search_example.py
```

## Como usar

1. Crie um app no [Mercado Livre Developers](https://developers.mercadolivre.com.br/apps/)
   e um app no [Shopee Open Platform](https://open.shopee.com) (mais o cadastro
   no programa de afiliados, se for usar `shopee/affiliate.py`).
2. `pip install -r requirements.txt`
3. `cp .env.example .env` e preencha com suas credenciais.
4. Gere a chave de criptografia dos tokens:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   e cole em `TOKEN_ENCRYPTION_KEY` no `.env`.
5. Rode `python -m examples.ml_oauth_flow` uma vez para autorizar sua conta
   Mercado Livre (abre o navegador, você loga e autoriza, o token é salvo
   criptografado em `tokens.enc`).
6. Rode `python -m examples.ml_search_example` para testar uma busca.
7. Para Shopee, o fluxo de autorização de loja é um pouco diferente (a
   Shopee redireciona para uma tela de "autorizar app" dentro do painel do
   vendedor) — use `ShopeeAuth.build_authorization_url()` e
   `ShopeeAuth.exchange_code()` como referência e adapte ao seu caso.

## O que foi levado a sério em segurança (e por quê)

**Segredos nunca em código-fonte.** `client_secret`, `partner_key` e afins só
existem em variáveis de ambiente (`.env`, ignorado no git). O `config.py`
falha alto e claro se alguma variável obrigatória estiver ausente, em vez de
silenciosamente usar um valor vazio.

**Tokens em disco, mas criptografados.** `storage/token_store.py` usa Fernet
(AES-128 + HMAC) e grava o arquivo com permissão `0600`. Isso é um
armazenamento de referência para uso local/pessoal — para produção de
verdade, troque por um secrets manager real (AWS Secrets Manager, GCP Secret
Manager, Vault), que separa fisicamente a chave dos dados e permite rotação
e auditoria. Deixei esse aviso repetido no docstring do módulo de propósito.

**Refresh token de uso único, tratado como tal.** Tanto Mercado Livre quanto
Shopee **rotacionam** o `refresh_token` a cada renovação — o antigo para de
funcionar assim que um novo é emitido. Os dois clientes (`MLClient`,
`ShopeeClient`) chamam um callback `on_token_refresh` imediatamente após
qualquer renovação, para você persistir o novo token *antes* de fazer
qualquer outra coisa. Se essa gravação falhar e o processo cair no meio, você
perde acesso e precisa reautorizar do zero — é um risco real desse desenho de
API, não uma falha do código.

**PKCE + `state` no fluxo OAuth do Mercado Livre.** PKCE é opcional na doc do
ML, mas incluí porque protege contra interceptação do `code` de autorização
em aplicações locais/desktop. O `state` é gerado com `secrets.token_urlsafe`
(criptograficamente seguro, não `random`) e validado no callback — sem isso,
o fluxo fica vulnerável a CSRF.

**Assinatura HMAC da Shopee, sem vazar o `partner_key`.** O `partner_key`
(e o `app_secret` da Affiliate API) só são usados localmente para calcular o
HMAC/SHA-256 — nunca trafegam na requisição. Inclui também
`verify_push_signature()` para validar webhooks recebidos da Shopee usando
`hmac.compare_digest` (comparação em tempo constante, evita timing attack) —
**nunca processe um payload de webhook sem validar a assinatura primeiro**.

**Timeouts e tratamento de rate limit em toda chamada HTTP.** Requests sem
timeout podem travar seu processo indefinidamente se a API não responder;
todas as chamadas usam `timeout=15`. Erros 429 são sinalizados explicitamente
como `MLAPIError`/`ShopeeAPIError` para você tratar backoff no chamador, em
vez de silenciosamente tentar de novo em loop.

**`sold_quantity` não é uma contagem exata.** Isso é uma limitação da própria
API do Mercado Livre (documentada de forma indireta, ver issues públicas do
SDK oficial), não deste código — deixei o aviso no docstring do
`mercadolivre/client.py` para não ser mal interpretado como métrica exata em
qualquer análise que você fizer em cima disso.

## O que este código deliberadamente NÃO faz

Não tenta contornar bloqueios de autenticação, scraping, ou qualquer limite
de acesso das plataformas — usa exclusivamente os endpoints e fluxos oficiais
documentados por Mercado Livre e Shopee. Não armazena nem loga
`client_secret`, `partner_key`, `access_token` ou `refresh_token` em texto
plano em nenhum momento (só em memória e no arquivo criptografado). Não
inclui credenciais de exemplo reais — `.env.example` só tem os nomes das
variáveis, vazios.



