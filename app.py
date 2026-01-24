import os
import uuid
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base

from authlib.integrations.starlette_client import OAuth, OAuthError

from openai import OpenAI

# -----------------------------
# ENV / SETTINGS
# -----------------------------
APP_NAME = os.getenv("APP_NAME", "Berke AI")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "berkekarakulak@gmail.com")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "")  # örn: https://mberke-ai.onrender.com

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-please")  # Render env'de değiştir
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "2592000"))  # 30 gün

# DB: varsa Postgres, yoksa SQLite (garanti kalksın diye)
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./app.db"

# Render Postgres bazen "postgres://" verir; SQLAlchemy "postgresql://" ister
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# -----------------------------
# DB SETUP
# -----------------------------
Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class UserStat(Base):
    __tablename__ = "user_stats"
    id = Column(String, primary_key=True)  # email veya guest:<id>
    email = Column(String, nullable=True)
    kind = Column(String, nullable=False)  # "google" | "guest"
    login_count = Column(Integer, default=0)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=True)
    meta = Column(Text, nullable=True)  # JSON string

Base.metadata.create_all(bind=engine)

def utcnow():
    return datetime.now(timezone.utc)

def db_upsert_login(user_id: str, kind: str, email: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
    db = SessionLocal()
    try:
        row = db.query(UserStat).filter(UserStat.id == user_id).first()
        now = utcnow()
        if row is None:
            row = UserStat(
                id=user_id,
                email=email,
                kind=kind,
                login_count=1,
                last_login_at=now,
                created_at=now,
                meta=json.dumps(meta or {}, ensure_ascii=False),
            )
            db.add(row)
        else:
            row.login_count = (row.login_count or 0) + 1
            row.last_login_at = now
            if email:
                row.email = email
            if meta:
                try:
                    old = json.loads(row.meta or "{}")
                except Exception:
                    old = {}
                old.update(meta)
                row.meta = json.dumps(old, ensure_ascii=False)
        db.commit()
    finally:
        db.close()

def db_list_stats(limit: int = 200) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        rows = (
            db.query(UserStat)
            .order_by(UserStat.last_login_at.desc().nullslast(), UserStat.created_at.desc().nullslast())
            .limit(limit)
            .all()
        )
        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "email": r.email,
                "kind": r.kind,
                "login_count": r.login_count,
                "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "meta": json.loads(r.meta) if r.meta else {},
            })
        return out
    finally:
        db.close()

# -----------------------------
# APP
# -----------------------------
app = FastAPI()

# Session middleware (OAuth için şart)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=SESSION_MAX_AGE,
    same_site="lax",
    https_only=bool(PUBLIC_BASE_URL.startswith("https://")),
)

# Static
app.mount("/static", StaticFiles(directory="static"), name="static")

# OAuth
oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# OpenAI client (API key yoksa chat endpoint düzgün hata döner)
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

def is_admin(email: Optional[str]) -> bool:
    return bool(email) and email.lower() == (ADMIN_EMAIL or "").lower()

def get_me(request: Request) -> Dict[str, Any]:
    s = request.session
    return {
        "logged_in": bool(s.get("kind")),
        "kind": s.get("kind"),
        "email": s.get("email"),
        "name": s.get("name"),
        "picture": s.get("picture"),
        "user_id": s.get("user_id"),
        "is_admin": is_admin(s.get("email")),
    }

# -----------------------------
# ROUTES: UI
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    p = Path("static/index.html")
    return p.read_text(encoding="utf-8")

@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(request: Request):
    me = get_me(request)
    if not me["is_admin"]:
        return HTMLResponse("403 Yetkisiz", status_code=403)
    p = Path("static/admin.html")
    return p.read_text(encoding="utf-8")

# -----------------------------
# ROUTES: AUTH
# -----------------------------
@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=400, detail="Google OAuth env eksik: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET")

    # callback URL
    base = PUBLIC_BASE_URL.rstrip("/") if PUBLIC_BASE_URL else str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user = token.get("userinfo")
        if not user:
            user = await oauth.google.parse_id_token(request, token)
    except OAuthError as e:
        return JSONResponse({"detail": f"Callback OAuth hata: {str(e)}"}, status_code=400)
    except Exception as e:
        return JSONResponse({"detail": f"Callback hata: {str(e)}"}, status_code=400)

    email = (user.get("email") or "").strip()
    name = user.get("name") or user.get("given_name") or "Kullanıcı"
    picture = user.get("picture")

    if not email:
        return JSONResponse({"detail": "Google email gelmedi"}, status_code=400)

    request.session["kind"] = "google"
    request.session["email"] = email
    request.session["name"] = name
    request.session["picture"] = picture
    request.session["user_id"] = f"google:{email.lower()}"

    db_upsert_login(
        user_id=request.session["user_id"],
        kind="google",
        email=email,
        meta={"name": name},
    )

    # sohbet ekranına dön
    return RedirectResponse(url="/#chat", status_code=302)

@app.post("/auth/guest")
async def auth_guest(request: Request):
    gid = request.session.get("user_id")
    if not gid or not str(gid).startswith("guest:"):
        gid = f"guest:{uuid.uuid4()}"
    request.session["kind"] = "guest"
    request.session["user_id"] = gid
    request.session["name"] = "Misafir"
    request.session.pop("email", None)
    request.session.pop("picture", None)

    db_upsert_login(user_id=gid, kind="guest", email=None, meta={})
    return {"ok": True, "user_id": gid}

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/api/me")
async def api_me(request: Request):
    return get_me(request)

# -----------------------------
# ROUTES: ADMIN API
# -----------------------------
@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    me = get_me(request)
    if not me["is_admin"]:
        raise HTTPException(status_code=403, detail="Yetkisiz")
    return {"items": db_list_stats()}

# -----------------------------
# ROUTES: CHAT + IMAGE
# -----------------------------
@app.post("/chat")
async def chat(request: Request):
    me = get_me(request)
    if not me["logged_in"]:
        raise HTTPException(status_code=401, detail="Önce giriş yap")

    body = await request.json()
    message = (body.get("message") or "").strip()
    history = body.get("history") or []

    if not message:
        return {"reply": ""}

    if client is None:
        return {"reply": "OpenAI API key tanımlı değil (OPENAI_API_KEY)."}

    # Basit, stabil prompt
    system = (
        "Sen samimi, dost canlısı bir asistansın. Kullanıcıyı ismiyle çağırma zorunluluğun yok. "
        "Kısa, net, yardımcı cevaplar ver. Küfür/hakaret yok."
    )

    msgs = [{"role": "system", "content": system}]

    # history: [{role:'user'|'assistant', content:'...'}]
    if isinstance(history, list):
        for h in history[-12:]:
            r = h.get("role")
            c = h.get("content")
            if r in ("user", "assistant") and isinstance(c, str):
                msgs.append({"role": r, "content": c})

    msgs.append({"role": "user", "content": message})

    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=msgs,
            temperature=0.7,
        )
        reply = resp.choices[0].message.content or ""
        return {"reply": reply}
    except Exception as e:
        return {"reply": f"Şu an teknik bir sorun var ama buradayım. ({str(e)})"}

@app.post("/api/image")
async def image_generate(request: Request):
    me = get_me(request)
    if not me["logged_in"]:
        raise HTTPException(status_code=401, detail="Önce giriş yap")

    body = await request.json()
    prompt = (body.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt boş")

    if client is None:
        raise HTTPException(status_code=400, detail="OPENAI_API_KEY yok")

    try:
        # Not: billing limit olursa UI zaten mesaj gösterecek
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1024",
        )
        b64 = img.data[0].b64_json
        return {"b64": b64}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Görsel üretim hata: {str(e)}")
