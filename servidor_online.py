import json
import os
import uuid
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

API_TOKEN = os.environ.get("COMABEM_API_TOKEN", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
WEB_ADMIN_LOGIN = os.environ.get("COMABEM_WEB_ADMIN_LOGIN", "").strip()
WEB_ADMIN_PASSWORD = os.environ.get("COMABEM_WEB_ADMIN_PASSWORD", "").strip()
WEB_ADMIN_LOGIN = os.environ.get("COMABEM_WEB_ADMIN_LOGIN", "").strip()
WEB_ADMIN_PASSWORD = os.environ.get("COMABEM_WEB_ADMIN_PASSWORD", "").strip()


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
            cur.execute("CREATE TABLE IF NOT EXISTS usuarios_web (id BIGSERIAL PRIMARY KEY, login TEXT NOT NULL UNIQUE, senha_hash TEXT NOT NULL, perfil TEXT NOT NULL DEFAULT 'ADMINISTRADOR', ativo BOOLEAN NOT NULL DEFAULT TRUE, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())")
            cur.execute("CREATE TABLE IF NOT EXISTS sessoes_web (token TEXT PRIMARY KEY, usuario_id BIGINT NOT NULL REFERENCES usuarios_web(id), expira_em TIMESTAMPTZ NOT NULL, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())")
            if WEB_ADMIN_LOGIN and WEB_ADMIN_PASSWORD:
                cur.execute("SELECT id FROM usuarios_web WHERE login=%s", (WEB_ADMIN_LOGIN,))
                if not cur.fetchone():
                    cur.execute("INSERT INTO usuarios_web(login,senha_hash,perfil) VALUES (%s,%s,%s)", (WEB_ADMIN_LOGIN, generate_password_hash(WEB_ADMIN_PASSWORD), "ADMINISTRADOR"))
            cur.execute("CREATE TABLE IF NOT EXISTS usuarios_web (id BIGSERIAL PRIMARY KEY, login TEXT NOT NULL UNIQUE, senha_hash TEXT NOT NULL, perfil TEXT NOT NULL DEFAULT 'ADMINISTRADOR', ativo BOOLEAN NOT NULL DEFAULT TRUE, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())")
            cur.execute("CREATE TABLE IF NOT EXISTS sessoes_web (token TEXT PRIMARY KEY, usuario_id BIGINT NOT NULL REFERENCES usuarios_web(id), expira_em TIMESTAMPTZ NOT NULL, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())")
            if WEB_ADMIN_LOGIN and WEB_ADMIN_PASSWORD:
                cur.execute("SELECT id FROM usuarios_web WHERE login=%s", (WEB_ADMIN_LOGIN,))
                if not cur.fetchone():
                    cur.execute("INSERT INTO usuarios_web(login,senha_hash,perfil) VALUES (%s,%s,%s)", (WEB_ADMIN_LOGIN, generate_password_hash(WEB_ADMIN_PASSWORD), "ADMINISTRADOR"))
        conn.commit()


@app.get("/health")
def health():
    try:
        init_db()
        return jsonify({"ok": True, "servico": "Coma Bem Online", "versao": "296", "banco": "postgres"})
    except Exception as e:
        return jsonify({"ok": False, "servico": "Coma Bem Online", "versao": "296", "erro": str(e)}), 500



def web_user_from_request():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if not token:
        return None
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT u.id,u.login,u.perfil FROM sessoes_web s JOIN usuarios_web u ON u.id=s.usuario_id WHERE s.token=%s AND s.expira_em>NOW() AND u.ativo=TRUE", (token,))
            row = cur.fetchone()
    return {"id": row[0], "login": row[1], "perfil": row[2]} if row else None


@app.post("/api/v1/web/login")
def web_login():
    data = request.get_json(silent=True) or {}
    login = str(data.get("login") or "").strip()
    senha = str(data.get("senha") or "")
    if not login or not senha:
        return jsonify({"ok": False, "erro": "login e senha obrigatorios"}), 400
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,login,senha_hash,perfil,ativo FROM usuarios_web WHERE login=%s", (login,))
            row = cur.fetchone()
            if not row or not row[4] or not check_password_hash(row[2], senha):
                return jsonify({"ok": False, "erro": "credenciais invalidas"}), 401
            token = uuid.uuid4().hex + uuid.uuid4().hex
            cur.execute("INSERT INTO sessoes_web(token,usuario_id,expira_em) VALUES (%s,%s,NOW()+INTERVAL '12 hours')", (token,row[0]))
        conn.commit()
    return jsonify({"ok": True, "token": token, "usuario": {"login": row[1], "perfil": row[3]}})


@app.get("/api/v1/web/me")
def web_me():
    user = web_user_from_request()
    if not user:
        return jsonify({"ok": False, "erro": "nao autorizado"}), 401
    return jsonify({"ok": True, "usuario": user})



def web_user_from_request():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if not token:
        return None
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT u.id,u.login,u.perfil FROM sessoes_web s JOIN usuarios_web u ON u.id=s.usuario_id WHERE s.token=%s AND s.expira_em>NOW() AND u.ativo=TRUE", (token,))
            row = cur.fetchone()
    return {"id": row[0], "login": row[1], "perfil": row[2]} if row else None


@app.post("/api/v1/web/login")
def web_login():
    data = request.get_json(silent=True) or {}
    login = str(data.get("login") or "").strip()
    senha = str(data.get("senha") or "")
    if not login or not senha:
        return jsonify({"ok": False, "erro": "login e senha obrigatorios"}), 400
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,login,senha_hash,perfil,ativo FROM usuarios_web WHERE login=%s", (login,))
            row = cur.fetchone()
            if not row or not row[4] or not check_password_hash(row[2], senha):
                return jsonify({"ok": False, "erro": "credenciais invalidas"}), 401
            token = uuid.uuid4().hex + uuid.uuid4().hex
            expira = datetime.now(timezone.utc) + timedelta(hours=12)
            cur.execute("INSERT INTO sessoes_web(token,usuario_id,expira_em) VALUES (%s,%s,%s)", (token,row[0],expira))
        conn.commit()
    return jsonify({"ok": True, "token": token, "usuario": {"login": row[1], "perfil": row[3]}})


@app.get("/api/v1/web/me")
def web_me():
    user = web_user_from_request()
    if not user:
        return jsonify({"ok": False, "erro": "nao autorizado"}), 401
    return jsonify({"ok": True, "usuario": user})


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
