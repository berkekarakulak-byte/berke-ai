import os
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware

from dotenv import load_dotenv

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, func
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

from authlib.integrations.starlette_client import OAuth
from openai import OpenAI

# =========================
# ENV
# =========================
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
BASE_URL = (os.getenv("BASE_URL") or "").strip()  # e.g. https://mberke-ai.onrender.com
ADMIN_PASSWORD = (os.getenv("ADMIN_PASSWORD") or "").strip()
SESSION_SECRET = (os.getenv("SESSION_SECRET") or "change-me-please").strip()

# =========================
# DB URL (FORCE psycopg3)
# =========================
DATABASE_URL = (os.getenv("DATABASE_URL") or "sqlite:///./app.db").strip()

# Render bazen postgres:// veya postgresql:// verir.
# SQLAlchemy'ın psycopg2'ye kaymasını engellemek için driver'ı ZORLA psycopg3 yapıyoruz.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)

print("DB_URL_EFFECTIVE=", DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =========================
# MODELS
# =========================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    provider = Column(String(50), default="google")  # google / guest
    provider_user_id = Column(String(255), nullable=True)  # google "sub"
    email = Column(String(255), nullable=True, index=True)
    name = Column(String(255), nullable=True)
    picture = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    logins = relationship("LoginEvent", back_populates="user", cascade="all, delete-orphan")
    messages = relationship("ChatMessage", back_populates="user", cascade="all, delete-orphan")


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    ip = Column(String(100), nullable=True)
    user_agent = Column(Text, nullable=True)

    user = relationship("User", back_populates="logins")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)

    role = Column(String(50))  # "user" / "assistant" / "system"
    content = Column(Text)

    pinned = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="messages")


def init_db():
    Base.metadata.create_all(bind=engine)


# =========================
# APP
# =========================
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True if (BASE_URL.startswith("https://")) else False,
)

# Static
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# OpenAI client (optional)
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# OAuth
oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# =========================
# HELPERS
# =========================
def db():
    return SessionLocal()

def now_utc():
    return datetime.now(timezone.utc)

def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    return request.session.get("user")

def require_user(request: Request):
    u = get_current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not logged in")
    return u

def is_admin_session(request: Request) -> bool:
    return bool(request.session.get("is_admin") is True)

def sanitize_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    return email.strip().lower()


# =========================
# STARTUP
# =========================
@app.on_event("startup")
def _startup():
    init_db()


# =========================
# UI (index)
# =========================
INDEX_PATH = os.path.join(os.path.dirname(__file__), "index.html")

@app.get("/", response_class=HTMLResponse)
def home():
    if os.path.exists(INDEX_PATH):
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>index.html not found</h1>"


# =========================
# AUTH ROUTES
# =========================
@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL):
        raise HTTPException(status_code=400, detail="Google OAuth is not configured.")
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL):
        raise HTTPException(status_code=400, detail="Google OAuth is not configured.")
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if not userinfo:
        # fallback
        userinfo = await oauth.google.parse_id_token(request, token)

    sub = str(userinfo.get("sub", "")).strip()
    email = sanitize_email(userinfo.get("email"))
    name = userinfo.get("name")
    picture = userinfo.get("picture")

    if not sub:
        raise HTTPException(status_code=400, detail="Google user id (sub) missing")

    session = db()
    try:
        user = session.query(User).filter(User.provider == "google", User.provider_user_id == sub).first()
        if not user and email:
            # if same email exists (rare)
            user = session.query(User).filter(User.email == email).first()

        if not user:
            user = User(
                provider="google",
                provider_user_id=sub,
                email=email,
                name=name,
                picture=picture,
                last_login_at=now_utc(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)
        else:
            user.email = email or user.email
            user.name = name or user.name
            user.picture = picture or user.picture
            user.last_login_at = now_utc()
            session.commit()

        # login event
        le = LoginEvent(
            user_id=user.id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        session.add(le)
        session.commit()

        request.session["user"] = {
            "id": user.id,
            "provider": user.provider,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    finally:
        session.close()

    return RedirectResponse(url="/")

@app.post("/auth/guest")
def auth_guest(request: Request):
    # guest user create/store
    session = db()
    try:
        user = User(
            provider="guest",
            provider_user_id=None,
            email=None,
            name="Guest",
            picture=None,
            last_login_at=now_utc(),
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        le = LoginEvent(
            user_id=user.id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        session.add(le)
        session.commit()

        request.session["user"] = {
            "id": user.id,
            "provider": user.provider,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    finally:
        session.close()

    return {"ok": True}

@app.post("/auth/logout")
def auth_logout(request: Request):
    request.session.pop("user", None)
    request.session.pop("is_admin", None)
    return {"ok": True}

@app.get("/api/me")
def api_me(request: Request):
    return {"user": get_current_user(request)}


# =========================
# ADMIN
# =========================
@app.post("/admin/login")
def admin_login(request: Request, payload: Dict[str, Any]):
    pw = str(payload.get("password", "")).strip()
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=400, detail="ADMIN_PASSWORD not set")
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
    if not is_admin_session(request):
        raise HTTPException(status_code=401, detail="Not admin")

    session = db()
    try:
        total_users = session.query(User).count()
        total_logins = session.query(LoginEvent).count()
        last_20 = (
            session.query(LoginEvent)
            .order_by(LoginEvent.id.desc())
            .limit(20)
            .all()
        )

        items = []
        for ev in last_20:
            u = session.query(User).filter(User.id == ev.user_id).first()
            items.append({
                "id": ev.id,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
                "user_id": ev.user_id,
                "email": u.email if u else None,
                "provider": u.provider if u else None,
                "ip": ev.ip,
            })

        return {
            "total_users": total_users,
            "total_logins": total_logins,
            "last_20_logins": items,
        }
    finally:
        session.close()


# =========================
# CHAT
# =========================
@app.get("/api/history")
def chat_history(request: Request):
    u = require_user(request)
    session = db()
    try:
        msgs = (
            session.query(ChatMessage)
            .filter(ChatMessage.user_id == u["id"])
            .order_by(ChatMessage.id.asc())
            .limit(200)
            .all()
        )
        return {
            "messages": [
                {
                    "id": m.id,
                    "role": m.role,
                    "content": m.content,
                    "pinned": bool(m.pinned),
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                }
                for m in msgs
            ]
        }
    finally:
        session.close()

@app.post("/api/pin")
def chat_pin(request: Request, payload: Dict[str, Any]):
    u = require_user(request)
    msg_id = int(payload.get("id", 0))
    pinned = bool(payload.get("pinned", True))

    session = db()
    try:
        m = session.query(ChatMessage).filter(ChatMessage.id == msg_id, ChatMessage.user_id == u["id"]).first()
        if not m:
            raise HTTPException(status_code=404, detail="Message not found")
        m.pinned = pinned
        session.commit()
        return {"ok": True}
    finally:
        session.close()

@app.post("/api/chat")
def chat_send(request: Request, payload: Dict[str, Any]):
    """
    payload: { message: "..." }
    """
    u = require_user(request)
    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=400, detail="Empty message")

    session = db()
    try:
        # save user msg
        um = ChatMessage(user_id=u["id"], role="user", content=message, pinned=False)
        session.add(um)
        session.commit()
        session.refresh(um)

        # If OpenAI configured, generate assistant reply.
        # If billing limit etc -> show error text but still keep app alive.
        assistant_text = "Şu an AI cevap veremiyor (API anahtarı yok ya da limit)."
        if client:
            try:
                # Keep minimal context: last 20 msgs
                last_msgs = (
                    session.query(ChatMessage)
                    .filter(ChatMessage.user_id == u["id"])
                    .order_by(ChatMessage.id.desc())
                    .limit(20)
                    .all()
                )
                # reverse to chronological
                last_msgs = list(reversed(last_msgs))

                chat_messages = []
                for m in last_msgs:
                    if m.role in ("user", "assistant", "system"):
                        chat_messages.append({"role": m.role, "content": m.content})

                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=chat_messages,
                )
                assistant_text = resp.choices[0].message.content or ""
            except Exception as e:
                assistant_text = f"AI hata: {str(e)}"

        am = ChatMessage(user_id=u["id"], role="assistant", content=assistant_text, pinned=False)
        session.add(am)
        session.commit()
        session.refresh(am)

        return {
            "user_message": {"id": um.id, "role": "user", "content": um.content, "pinned": um.pinned},
            "assistant_message": {"id": am.id, "role": "assistant", "content": am.content, "pinned": am.pinned},
        }
    finally:
        session.close()


# =========================
# IMAGE (keeps endpoint, returns nice error when billing)
# =========================
@app.post("/api/image")
def generate_image(request: Request, payload: Dict[str, Any]):
    u = require_user(request)
    prompt = str(payload.get("prompt", "")).strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Empty prompt")

    if not client:
        return JSONResponse(status_code=400, content={"error": "OPENAI_API_KEY yok. Görsel için API key gerekli."})

    try:
        # NOTE: Görsel için billing şart. Limit varsa 400 döner, UI gösterecek.
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1024",
        )
        b64 = img.data[0].b64_json
        return {"b64": b64}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/health")
def health():
    return {"ok": True}
