import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

API_TOKEN = os.environ.get('COMABEM_API_TOKEN', '').strip()
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
WEB_ADMIN_LOGIN = os.environ.get('COMABEM_WEB_ADMIN_LOGIN', '').strip()
WEB_ADMIN_PASSWORD = os.environ.get('COMABEM_WEB_ADMIN_PASSWORD', '').strip()
HOMOLOG_ORIGIN = 'https://comabem-homologacao.onrender.com'

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_conn():
    if not DATABASE_URL: raise RuntimeError('DATABASE_URL nao configurado')
    import psycopg
    return psycopg.connect(DATABASE_URL)

def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('CREATE TABLE IF NOT EXISTS eventos (id BIGSERIAL PRIMARY KEY, loja_id TEXT NOT NULL, dispositivo_id TEXT NOT NULL, evento_id TEXT NOT NULL UNIQUE, tipo TEXT NOT NULL, payload JSONB NOT NULL, criado_em TIMESTAMPTZ NOT NULL, recebido_em TIMESTAMPTZ NOT NULL DEFAULT NOW())')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_eventos_loja_id_id ON eventos(loja_id,id)')
            cur.execute("CREATE TABLE IF NOT EXISTS usuarios_web (id BIGSERIAL PRIMARY KEY, login TEXT NOT NULL UNIQUE, senha_hash TEXT NOT NULL, perfil TEXT NOT NULL DEFAULT 'ADMINISTRADOR', ativo BOOLEAN NOT NULL DEFAULT TRUE, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())")
            cur.execute('CREATE TABLE IF NOT EXISTS sessoes_web (token TEXT PRIMARY KEY, usuario_id BIGINT NOT NULL REFERENCES usuarios_web(id), expira_em TIMESTAMPTZ NOT NULL, criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW())')
            if WEB_ADMIN_LOGIN and WEB_ADMIN_PASSWORD:
                cur.execute('SELECT id FROM usuarios_web WHERE login=%s',(WEB_ADMIN_LOGIN,))
                if not cur.fetchone(): cur.execute('INSERT INTO usuarios_web(login,senha_hash,perfil) VALUES (%s,%s,%s)',(WEB_ADMIN_LOGIN,generate_password_hash(WEB_ADMIN_PASSWORD),'ADMINISTRADOR'))
        conn.commit()

@app.after_request
def cors(resp):
    if request.headers.get('Origin') == HOMOLOG_ORIGIN:
        resp.headers['Access-Control-Allow-Origin'] = HOMOLOG_ORIGIN
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Vary'] = 'Origin'
    return resp

def machine_auth():
    auth=request.headers.get('Authorization','')
    return bool(API_TOKEN and auth == f'Bearer {API_TOKEN}')

def web_user():
    auth=request.headers.get('Authorization','')
    token=auth[7:].strip() if auth.startswith('Bearer ') else ''
    if not token: return None
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT u.id,u.login,u.perfil FROM sessoes_web s JOIN usuarios_web u ON u.id=s.usuario_id WHERE s.token=%s AND s.expira_em>NOW() AND u.ativo=TRUE',(token,))
            r=cur.fetchone()
    return {'id':r[0],'login':r[1],'perfil':r[2]} if r else None

@app.get('/health')
def health():
    try:
        init_db(); return jsonify({'ok':True,'servico':'Coma Bem Online','versao':'308','banco':'postgres'})
    except Exception as e: return jsonify({'ok':False,'servico':'Coma Bem Online','versao':'308','erro':str(e)}),500

@app.post('/api/v1/web/login')
def login_web():
    d=request.get_json(silent=True) or {}; login=str(d.get('login') or '').strip(); senha=str(d.get('senha') or '')
    if not login or not senha: return jsonify({'ok':False,'erro':'login e senha obrigatorios'}),400
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,login,senha_hash,perfil,ativo FROM usuarios_web WHERE login=%s',(login,)); r=cur.fetchone()
            if not r or not r[4] or not check_password_hash(r[2],senha): return jsonify({'ok':False,'erro':'credenciais invalidas'}),401
            token=uuid.uuid4().hex+uuid.uuid4().hex
            cur.execute("INSERT INTO sessoes_web(token,usuario_id,expira_em) VALUES (%s,%s,NOW()+INTERVAL '12 hours')",(token,r[0]))
        conn.commit()
    return jsonify({'ok':True,'token':token,'usuario':{'login':r[1],'perfil':r[3]}})

@app.get('/api/v1/web/me')
def me_web():
    u=web_user()
    return jsonify({'ok':True,'usuario':u}) if u else (jsonify({'ok':False,'erro':'nao autorizado'}),401)

def auth_eventos():
    return machine_auth() or bool(web_user())

@app.post('/api/v1/eventos')
def receber_evento():
    if not auth_eventos(): return jsonify({'ok':False,'erro':'nao autorizado'}),401
    d=request.get_json(silent=True) or {}; obrig=['loja_id','dispositivo_id','tipo','payload']; falt=[k for k in obrig if d.get(k) in (None,'')]
    if falt: return jsonify({'ok':False,'erro':'campos obrigatorios','faltando':falt}),400
    evento_id=str(d.get('evento_id') or uuid.uuid4()); criado=str(d.get('criado_em') or now_iso()); init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO eventos(loja_id,dispositivo_id,evento_id,tipo,payload,criado_em) VALUES (%s,%s,%s,%s,%s::jsonb,%s::timestamptz) ON CONFLICT(evento_id) DO NOTHING RETURNING id',(str(d['loja_id']),str(d['dispositivo_id']),evento_id,str(d['tipo']),json.dumps(d['payload'],ensure_ascii=False),criado)); row=cur.fetchone()
            if not row:
                cur.execute('SELECT id FROM eventos WHERE evento_id=%s',(evento_id,)); row=cur.fetchone()
        conn.commit()
    return jsonify({'ok':True,'evento_id':evento_id,'id':row[0] if row else None})

@app.get('/api/v1/eventos')
def listar_eventos():
    if not auth_eventos(): return jsonify({'ok':False,'erro':'nao autorizado'}),401
    loja=(request.args.get('loja_id') or '').strip()
    if not loja: return jsonify({'ok':False,'erro':'loja_id obrigatorio'}),400
    try: depois=int(request.args.get('depois','0'))
    except ValueError: depois=0
    init_db()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,loja_id,dispositivo_id,evento_id,tipo,payload,criado_em,recebido_em FROM eventos WHERE loja_id=%s AND id>%s ORDER BY id ASC LIMIT 1000',(loja,depois)); rows=cur.fetchall()
    ev=[{'id':r[0],'loja_id':r[1],'dispositivo_id':r[2],'evento_id':r[3],'tipo':r[4],'payload':r[5],'criado_em':r[6].isoformat() if r[6] else None,'recebido_em':r[7].isoformat() if r[7] else None} for r in rows]
    return jsonify({'ok':True,'eventos':ev,'ultimo_id':ev[-1]['id'] if ev else depois})

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','8080')))
