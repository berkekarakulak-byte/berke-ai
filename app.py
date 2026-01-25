import os
import time
import secrets
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.proxy_headers import ProxyHeadersMiddleware

from authlib.integrations.starlette_client import OAuth, OAuthError

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from openai import OpenAI


# =========================
# ENV
# =========================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

# Render ortam tespiti
IS_PROD = (os.getenv("RENDER") == "true") or (os.getenv("ENV") == "prod")
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip() or secrets.token_urlsafe(32)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()  # Render'da mutlaka ekle

RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
# Render Postgres URL genelde "postgresql://..." gelir.
# SQLAlchemy + psycopg için "postgresql+psycopg://..." olmalı.
def normalize_db_url(url: str) -> str:
    if not url:
        return ""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    return url

DATABASE_URL = normalize_db_url(RAW_DATABASE_URL)

# =========================
# APP
# =========================
app = FastAPI()

# Proxy headers => Google redirect_uri https doğru olsun (Render arkasında şart)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# CORS (tek sayfa frontend için rahat)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # istersen domaininle sınırlarsın
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session => admin ve login kalıcılığı
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=IS_PROD,  # Render=https => True, local=http => False
)

# =========================
# OpenAI Client (opsiyonel)
# =========================
client: Optional[OpenAI] = None
if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)

# =========================
# DB
# =========================
engine: Optional[Engine] = None
if DATABASE_URL:
    # Postgres için connect_args boş.
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

def db_exec(sql: str, params: Optional[dict] = None):
    if not engine:
        raise HTTPException(status_code=500, detail="Database not configured (DATABASE_URL missing).")
    with engine.begin() as conn:
        return conn.execute(text(sql), params or {})

def ensure_tables():
    if not engine:
        return
    # basit tablo: users + logins
    db_exec("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        name TEXT,
        picture TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
    );
    """)
    db_exec("""
    CREATE TABLE IF NOT EXISTS login_events (
        id SERIAL PRIMARY KEY,
        email TEXT,
        provider TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    """)

@app.on_event("startup")
def on_startup():
    ensure_tables()

# =========================
# OAuth (Google)
# =========================
oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# =========================
# Helpers
# =========================
def get_user(request: Request) -> Optional[dict]:
    return request.session.get("user")

def require_user(request: Request) -> dict:
    u = get_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not logged in")
    return u

def is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))

def require_admin(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Not admin")

def record_login(email: str, name: str = "", picture: str = "", provider: str = "unknown"):
    if not engine:
        return
    # upsert user
    db_exec("""
    INSERT INTO users (email, name, picture, last_login)
    VALUES (:email, :name, :picture, NOW())
    ON CONFLICT (email)
    DO UPDATE SET name = EXCLUDED.name, picture = EXCLUDED.picture, last_login = NOW();
    """, {"email": email, "name": name or "", "picture": picture or ""})

    db_exec("""
    INSERT INTO login_events (email, provider) VALUES (:email, :provider);
    """, {"email": email, "provider": provider})


# =========================
# Static Frontend
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    # index dosyan static/index.html olarak duruyor
    path = os.path.join("static", "index.html")
    if not os.path.exists(path):
        return HTMLResponse(
            "<h2>index.html bulunamadı</h2><p>Dosya yolu: <b>static/index.html</b></p>",
            status_code=500
        )
    return FileResponse(path)


# =========================
# Auth Routes
# =========================
@app.get("/me")
def me(request: Request):
    u = request.session.get("user")
    return {
        "user": u,
        "is_admin": bool(request.session.get("is_admin")),
        "is_prod": IS_PROD,
    }

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.post("/login/guest")
def login_guest(request: Request, payload: dict = Body(default={})):
    # Misafir: random id ve label
    guest_id = payload.get("guest_id") or f"guest_{secrets.token_hex(4)}"
    request.session["user"] = {
        "email": f"{guest_id}@guest.local",
        "name": "Misafir",
        "picture": "",
        "provider": "guest",
    }
    request.session["is_admin"] = False
    return {"ok": True, "user": request.session["user"]}


@app.get("/login/google")
async def login_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=500, detail="Google OAuth env missing (GOOGLE_CLIENT_ID/SECRET).")

    # callback URL kesin: https://domain/auth/google
    redirect_uri = str(request.url_for("auth_google"))
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google")
async def auth_google(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        # Google "invalid_request" gibi şeyleri burada görürsün
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    userinfo = token.get("userinfo")
    if not userinfo:
        # bazı durumlarda userinfo ayrı çekilir
        userinfo = await oauth.google.parse_id_token(request, token)

    email = (userinfo.get("email") or "").strip()
    name = (userinfo.get("name") or "").strip()
    picture = (userinfo.get("picture") or "").strip()

    if not email:
        return JSONResponse({"ok": False, "error": "Google did not return email"}, status_code=400)

    request.session["user"] = {
        "email": email,
        "name": name or email.split("@")[0],
        "picture": picture,
        "provider": "google",
    }
    request.session["is_admin"] = False

    # DB login kaydı
    record_login(email=email, name=name, picture=picture, provider="google")

    return RedirectResponse(url="/")


# =========================
# Admin Routes
# =========================
@app.post("/admin/login")
def admin_login(request: Request, payload: dict = Body(...)):
    pw = (payload.get("password") or "").strip()
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD env is missing on server.")
    if pw != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Wrong password")

    request.session["is_admin"] = True
    return {"ok": True}

@app.post("/admin/logout")
def admin_logout(request: Request):
    request.session["is_admin"] = False
    return {"ok": True}

@app.get("/admin/stats")
def admin_stats(request: Request):
    require_admin(request)

    if not engine:
        return {"ok": True, "db": False, "users": [], "logins_last_50": []}

    users = db_exec("""
        SELECT email, name, picture, created_at, last_login
        FROM users
        ORDER BY last_login DESC NULLS LAST
        LIMIT 200;
    """).mappings().all()

    logins = db_exec("""
        SELECT email, provider, created_at
        FROM login_events
        ORDER BY created_at DESC
        LIMIT 50;
    """).mappings().all()

    return {"ok": True, "db": True, "users": list(users), "logins_last_50": list(logins)}


# =========================
# Chat API
# =========================
@app.post("/api/chat")
def api_chat(request: Request, payload: dict = Body(...)):
    user = require_user(request)

    if not client:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY missing on server.")

    message = (payload.get("message") or "").strip()
    history = payload.get("history") or []  # list[{role, content}]
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    # history güvenliği: rol filtrele
    safe_history: List[Dict[str, str]] = []
    for item in history[-12:]:
        r = item.get("role")
        c = item.get("content")
        if r in ("system", "user", "assistant") and isinstance(c, str):
            safe_history.append({"role": r, "content": c})

    safe_history.append({"role": "user", "content": message})

    try:
        resp = client.chat.completions.create(
            model=os.getenv("CHAT_MODEL", "gpt-4o-mini"),
            messages=safe_history,
            temperature=0.7,
        )
        answer = resp.choices[0].message.content or ""
        return {"ok": True, "answer": answer, "user": user}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {e}")


# =========================
# Image API (şimdilik kalsın)
# =========================
@app.post("/api/image")
def api_image(request: Request, payload: dict = Body(...)):
    require_user(request)
    if not client:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY missing on server.")

    prompt = (payload.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

    # Billing limit vs. için hata mesajını UI'ya net döndürelim
    try:
        # Eğer hesabında görüntü üretim açıksa:
        # Not: Model adı değişebilir; env'den alıyoruz.
        image_model = os.getenv("IMAGE_MODEL", "gpt-image-1")
        result = client.images.generate(
            model=image_model,
            prompt=prompt,
            size="1024x1024",
        )
        # openai python sdk genelde b64 veya url döndürebilir (modele göre)
        data0 = result.data[0]
        # url varsa
        if getattr(data0, "url", None):
            return {"ok": True, "url": data0.url}
        # b64 varsa
        if getattr(data0, "b64_json", None):
            return {"ok": True, "b64": data0.b64_json}
        return {"ok": False, "error": "Unknown image response format"}
    except Exception as e:
        # Billing hard limit gibi hataları aynen göster
        raise HTTPException(status_code=400, detail=f"Görsel üretim hata: {e}")


# =========================
# Health
# =========================
@app.get("/health")
def health():
    return {"ok": True, "db": bool(engine), "prod": IS_PROD}
