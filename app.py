import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime, Text, Boolean
)
from sqlalchemy.orm import sessionmaker, declarative_base

from authlib.integrations.starlette_client import OAuth

from openai import OpenAI

# -----------------------------
# Config
# -----------------------------
APP_NAME = "Berke AI"

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
if not SESSION_SECRET:
    # local dev fallback (Render'da mutlaka env set et)
    SESSION_SECRET = "dev-secret-change-me"

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "berkekarakulak@gmail.com").strip().lower()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "").strip()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./berke_ai.db"

# Render bazen postgres:// verir, SQLAlchemy için postgresql:// daha stabil
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# -----------------------------
# DB
# -----------------------------
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String(64), primary_key=True)           # internal uuid
    email = Column(String(320), unique=True, index=True)
    name = Column(String(200), default="")
    avatar = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    login_count = Column(Integer, default=0)
    is_admin = Column(Boolean, default=False)

class GuestStats(Base):
    __tablename__ = "guest_stats"
    id = Column(String(64), primary_key=True)           # single row: "guest"
    guest_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        row = db.get(GuestStats, "guest")
        if not row:
            row = GuestStats(id="guest", guest_count=0)
            db.add(row)
            db.commit()
    finally:
        db.close()

# -----------------------------
# OpenAI client (safe init)
# -----------------------------
client: Optional[OpenAI] = None
if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        # server yine çalışsın; chat endpoint hata döner
        client = None

# -----------------------------
# FastAPI
# -----------------------------
app = FastAPI(title=APP_NAME)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,  # Render https
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

@app.on_event("startup")
def _startup():
    init_db()

# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_session_user(request: Request):
    """
    Returns dict: {mode, email, name, user_id, is_admin}
    """
    s = request.session
    if s.get("mode") == "google" and s.get("email"):
        return {
            "mode": "google",
            "email": s.get("email", ""),
            "name": s.get("name", ""),
            "user_id": s.get("user_id", ""),
            "is_admin": bool(s.get("is_admin", False)),
        }
    if s.get("mode") == "guest":
        return {
            "mode": "guest",
            "email": "",
            "name": s.get("guest_name", "Misafir"),
            "user_id": s.get("guest_id", ""),
            "is_admin": False,
        }
    return None

def require_admin(request: Request):
    u = get_session_user(request)
    if not u or not u.get("is_admin"):
        raise HTTPException(status_code=403, detail="Yetkisiz")
    return u

def upsert_user_on_login(email: str, name: str, avatar: str) -> dict:
    email_l = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email_l).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                email=email_l,
                name=name or "",
                avatar=avatar or "",
                created_at=datetime.now(timezone.utc),
                login_count=0,
            )
            db.add(user)

        user.name = name or user.name or ""
        user.avatar = avatar or user.avatar or ""
        user.last_login_at = datetime.now(timezone.utc)
        user.login_count = (user.login_count or 0) + 1
        user.is_admin = (email_l == ADMIN_EMAIL)

        db.commit()
        db.refresh(user)

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "avatar": user.avatar,
            "login_count": user.login_count,
            "is_admin": user.is_admin,
        }
    finally:
        db.close()

def bump_guest_count():
    db = SessionLocal()
    try:
        row = db.get(GuestStats, "guest")
        if not row:
            row = GuestStats(id="guest", guest_count=0)
            db.add(row)
        row.guest_count = (row.guest_count or 0) + 1
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()

# -----------------------------
# Routes: UI
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h1>index.html bulunamadı</h1>", status_code=500)
    return HTMLResponse(index_path.read_text(encoding="utf-8"))

@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(request: Request):
    # basit koruma: admin değilse 403
    require_admin(request)
    admin_path = STATIC_DIR / "admin.html"
    if admin_path.exists():
        return HTMLResponse(admin_path.read_text(encoding="utf-8"))
    # admin.html yoksa fallback
    return HTMLResponse(
        "<h2>Admin UI dosyası yok</h2><p>static/admin.html ekleyebilirsin.</p>",
        status_code=200
    )

# -----------------------------
# Routes: Auth
# -----------------------------
@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=500, detail="Google OAuth ayarlı değil (CLIENT_ID/SECRET yok).")
    redirect_uri = GOOGLE_REDIRECT_URI or str(request.url_for("auth_google_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=500, detail="Google OAuth ayarlı değil (CLIENT_ID/SECRET yok).")

    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo") or {}
        # fallback: id_token parse
        if not userinfo:
            userinfo = await oauth.google.parse_id_token(request, token)

        email = (userinfo.get("email") or "").strip()
        name = (userinfo.get("name") or userinfo.get("given_name") or "").strip()
        avatar = (userinfo.get("picture") or "").strip()

        if not email:
            raise HTTPException(status_code=400, detail="Google'dan email alınamadı.")

        up = upsert_user_on_login(email=email, name=name, avatar=avatar)

        # session'a yaz
        request.session.clear()
        request.session["mode"] = "google"
        request.session["email"] = up["email"]
        request.session["name"] = up["name"]
        request.session["user_id"] = up["id"]
        request.session["is_admin"] = bool(up["is_admin"])

        # direkt sohbete dön (UI zaten / üzerinde)
        return RedirectResponse(url="/", status_code=302)

    except HTTPException:
        raise
    except Exception as e:
        # kullanıcı görsün diye
        return JSONResponse({"detail": f"Callback hata: {str(e)}"}, status_code=400)

@app.post("/auth/guest")
async def auth_guest(request: Request):
    data = await request.json()
    guest_name = (data.get("name") or "Misafir").strip()[:40]
    guest_id = str(uuid.uuid4())

    request.session.clear()
    request.session["mode"] = "guest"
    request.session["guest_name"] = guest_name
    request.session["guest_id"] = guest_id

    bump_guest_count()
    return {"ok": True, "mode": "guest", "name": guest_name}

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/api/me")
def api_me(request: Request):
    u = get_session_user(request)
    if not u:
        return {"logged_in": False}
    return {"logged_in": True, **u}

# -----------------------------
# Routes: Admin API
# -----------------------------
@app.get("/api/admin/stats")
def admin_stats(request: Request):
    require_admin(request)
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.last_login_at.desc()).limit(200).all()
        guest = db.get(GuestStats, "guest")
        return {
            "guest_count": guest.guest_count if guest else 0,
            "users": [
                {
                    "email": u.email,
                    "name": u.name,
                    "login_count": u.login_count,
                    "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                    "is_admin": u.is_admin,
                }
                for u in users
            ],
        }
    finally:
        db.close()

# -----------------------------
# Routes: Chat / Image
# -----------------------------
@app.post("/api/chat")
async def chat(request: Request):
    u = get_session_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Önce giriş yap (Google / Misafir).")

    data = await request.json()
    message = (data.get("message") or "").strip()
    if not message:
        return {"reply": "", "ts": now_iso()}

    # Persona: samimi, dostça
    persona = (
        "Sen samimi, cana yakın, kısa ve net konuşan bir yardımcı botsun. "
        "Kullanıcıya 'kanka', 'bro' gibi sıcak bir dille yaklaşabilirsin ama saygıyı koru. "
        "Gereksiz uzatma, pratik çözüm öner."
    )

    # Basit memory: (şimdilik DB'ye sohbet yazmıyoruz; istersen sonraki adımda ekleriz)
    # Burada sadece kullanıcı emailini gösterip kişiselleştirme yapıyoruz.
    user_label = u.get("email") or u.get("name") or "Misafir"

    if not client:
        return {
            "reply": "Şu an teknik bir sorun var ama buradayım. (OpenAI anahtarı / bağlantı kontrol et)",
            "ts": now_iso()
        }

    try:
        # Model adını senin projendeki mevcut halinle uyumlu tutmak için:
        # gpt-4o-mini genelde hızlı/ucuz; yoksa gpt-4.1-mini de olabilir.
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": persona},
                {"role": "system", "content": f"Kullanıcı etiketi: {user_label}"},
                {"role": "user", "content": message},
            ],
            temperature=0.7,
        )
        reply = resp.choices[0].message.content or ""
        return {"reply": reply, "ts": now_iso()}
    except Exception as e:
        return {"reply": f"Şu an cevap veremedim: {str(e)}", "ts": now_iso()}

@app.post("/api/image")
async def image_generate(request: Request):
    """
    UI'da buton kalsın diye endpoint var.
    Billing limit varsa 400 dönecek. UI bunu gösterir.
    """
    u = get_session_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Önce giriş yap (Google / Misafir).")

    data = await request.json()
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt boş.")

    if not client:
        raise HTTPException(status_code=500, detail="OpenAI client yok (API key).")

    try:
        # Görsel modeli (DALL·E / gpt-image-1 vs)
        image_model = os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1")
        out = client.images.generate(
            model=image_model,
            prompt=prompt,
            size="1024x1024",
        )
        # base64 dönebilir; url dönebilir. Biz ikisini de handle edelim.
        img = out.data[0]
        image_url = getattr(img, "url", None)
        b64 = getattr(img, "b64_json", None)
        return {"url": image_url, "b64": b64, "ts": now_iso()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Görsel üretim hata: {str(e)}")
