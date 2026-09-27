# Coma Bem Online

Backend HTTPS de sincronizacao do sistema Coma Bem.

## Endpoints

- `GET /health`
- `POST /api/v1/eventos`
- `GET /api/v1/eventos?loja_id=LOJA&depois=0`

As rotas `/api/v1/*` usam:

`Authorization: Bearer <COMABEM_API_TOKEN>`

Banco: PostgreSQL via `DATABASE_URL`.

Versao do backend: 296.
