import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

API_TOKEN = os.environ.get("COMABEM_API_TOKEN", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def require_auth():
    auth = request.headers.get("Authorization", "")
    if not API_TOKEN:
        return jsonify({"ok": False, "erro": "COMABEM_API_TOKEN nao configurado"}), 500
    if auth != f"Bearer {API_TOKEN}":
        return jsonify({"ok": False, "erro": "nao autorizado"}), 401
    return None


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL nao configurado")
    import psycopg
    return psycopg.connect(DATABASE_URL)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS eventos (
                    id BIGSERIAL PRIMARY KEY,
                    loja_id TEXT NOT NULL,
                    dispositivo_id TEXT NOT NULL,
                    evento_id TEXT NOT NULL UNIQUE,
                    tipo TEXT NOT NULL,
                    payload JSONB NOT NULL,
                    criado_em TIMESTAMPTZ NOT NULL,
                    recebido_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_eventos_loja_id_id ON eventos(loja_id, id)")
        conn.commit()


@app.get("/health")
def health():
    try:
        init_db()
        return jsonify({"ok": True, "servico": "Coma Bem Online", "versao": "296", "banco": "postgres"})
    except Exception as e:
        return jsonify({"ok": False, "servico": "Coma Bem Online", "versao": "296", "erro": str(e)}), 500


@app.post("/api/v1/eventos")
def receber_evento():
    denied = require_auth()
    if denied:
        return denied

    data = request.get_json(silent=True) or {}
    obrig = ["loja_id", "dispositivo_id", "tipo", "payload"]
    faltando = [k for k in obrig if data.get(k) in (None, "")]
    if faltando:
        return jsonify({"ok": False, "erro": "campos obrigatorios", "faltando": faltando}), 400

    evento_id = str(data.get("evento_id") or uuid.uuid4())
    criado_em = str(data.get("criado_em") or now_iso())

    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO eventos
                    (loja_id, dispositivo_id, evento_id, tipo, payload, criado_em)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::timestamptz)
                ON CONFLICT (evento_id) DO NOTHING
                RETURNING id
                """,
                (
                    str(data["loja_id"]),
                    str(data["dispositivo_id"]),
                    evento_id,
                    str(data["tipo"]),
                    json.dumps(data["payload"], ensure_ascii=False),
                    criado_em,
                ),
            )
            row = cur.fetchone()
        conn.commit()

    return jsonify({"ok": True, "evento_id": evento_id, "id": row[0] if row else None})


@app.get("/api/v1/eventos")
def listar_eventos():
    denied = require_auth()
    if denied:
        return denied

    loja_id = (request.args.get("loja_id") or "").strip()
    if not loja_id:
        return jsonify({"ok": False, "erro": "loja_id obrigatorio"}), 400

    try:
        depois = int(request.args.get("depois", "0"))
    except ValueError:
        depois = 0

    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, loja_id, dispositivo_id, evento_id, tipo, payload, criado_em, recebido_em
                FROM eventos
                WHERE loja_id = %s AND id > %s
                ORDER BY id ASC
                LIMIT 1000
                """,
                (loja_id, depois),
            )
            rows = cur.fetchall()

    eventos = []
    for r in rows:
        eventos.append(
            {
                "id": r[0],
                "loja_id": r[1],
                "dispositivo_id": r[2],
                "evento_id": r[3],
                "tipo": r[4],
                "payload": r[5],
                "criado_em": r[6].isoformat() if r[6] else None,
                "recebido_em": r[7].isoformat() if r[7] else None,
            }
        )
    return jsonify({"ok": True, "eventos": eventos, "ultimo_id": eventos[-1]["id"] if eventos else depois})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
