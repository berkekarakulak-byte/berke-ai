import os
import json
import secrets
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware

from authlib.integrations.starlette_client import OAuth, OAuthError

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

from openai import OpenAI

# ----------------------------
# ENV
# ----------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip() or secrets.token_urlsafe(32)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()  # set on Render

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

# Render Postgres often gives "postgresql://"
# SQLAlchemy + psycopg3 wants "postgresql+psycopg://"
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# fallback local
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./app.db"

# ----------------------------
# DB
# ----------------------------
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)

    provider = Column(String(32), nullable=False, default="guest")  # google/guest
    email = Column(String(255), nullable=True, index=True)
    name = Column(String(255), nullable=True)
    picture = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    logins = relationship("LoginEvent", back_populates="user", cascade="all, delete-orphan")
    messages = relationship("ChatMessage", back_populates="user", cascade="all, delete-orphan")
    pins = relationship("PinnedMessage", back_populates="user", cascade="all, delete-orphan")

class LoginEvent(Base):
    __tablename__ = "login_events"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ip = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)

    user = relationship("User", back_populates="logins")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    role = Column(String(16), nullable=False)  # user/assistant/system
    content = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="messages")

class PinnedMessage(Base):
    __tablename__ = "pinned_messages"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message_id = Column(Integer, ForeignKey("chat_messages.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="pins")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)

# ----------------------------
# APP
# ----------------------------
app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,  # Render uses HTTPS
)

# static
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ----------------------------
# OAuth (Google)
# ----------------------------
oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# ----------------------------
# OpenAI
# ----------------------------
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# ----------------------------
# helpers
# ----------------------------
def _now():
    return datetime.now(timezone.utc)

def get_db():
    return SessionLocal()

def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    return request.session.get("user")

def require_user(request: Request) -> Dict[str, Any]:
    u = get_current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not logged in")
    return u

def ensure_guest_user(request: Request) -> Dict[str, Any]:
    """Creates a guest session user (and DB user) if not exists."""
    u = get_current_user(request)
    if u:
        return u

    guest_id = "guest_" + secrets.token_hex(8)
    db = get_db()
    try:
        user = User(provider="guest", email=None, name="Guest", picture=None)
        db.add(user)
        db.commit()
        db.refresh(user)

        request.session["user"] = {
            "id": user.id,
            "provider": "guest",
            "email": None,
            "name": "Guest",
            "picture": None,
        }
        request.session["guest_id"] = guest_id

        # login event
        ev = LoginEvent(
            user_id=user.id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(ev)
        db.commit()

        return request.session["user"]
    finally:
        db.close()

def upsert_google_user(db, email: str, name: str, picture: str) -> User:
    user = db.query(User).filter(User.provider == "google", User.email == email).first()
    if user:
        user.name = name
        user.picture = picture
        db.commit()
        db.refresh(user)
        return user

    user = User(provider="google", email=email, name=name, picture=picture)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# ----------------------------
# Routes: UI
# ----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    # Always serve the SPA file from /static/index.html
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("static/index.html missing", status_code=500)
    return FileResponse(index_path)

@app.get("/health")
def health():
    return {"ok": True, "time": _now().isoformat()}

# ----------------------------
# Auth routes
# ----------------------------
@app.get("/auth/guest")
def auth_guest(request: Request):
    ensure_guest_user(request)
    return RedirectResponse(url="/", status_code=302)

@app.get("/login/google")
async def login_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(400, detail="Google OAuth not configured")
    redirect_uri = str(request.url_for("auth_google_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google")
async def auth_google_callback(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(400, detail="Google OAuth not configured")
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(400, detail=f"OAuth error: {str(e)}")

    userinfo = token.get("userinfo")
    if not userinfo:
        # Some flows return id_token; Authlib can parse userinfo via /userinfo automatically,
        # but if not present, try fetch:
        userinfo = await oauth.google.userinfo(request, token=token)

    email = userinfo.get("email")
    name = userinfo.get("name") or userinfo.get("given_name") or "User"
    picture = userinfo.get("picture")

    if not email:
        raise HTTPException(400, detail="Google did not return email")

    db = get_db()
    try:
        user = upsert_google_user(db, email=email, name=name, picture=picture)

        request.session["user"] = {
            "id": user.id,
            "provider": "google",
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }

        ev = LoginEvent(
            user_id=user.id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(ev)
        db.commit()

    finally:
        db.close()

    return RedirectResponse(url="/", status_code=302)

@app.post("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}

# ----------------------------
# Admin auth (simple)
# ----------------------------
@app.post("/admin/login")
async def admin_login(request: Request):
    data = await request.json()
    pwd = (data.get("password") or "").strip()
    if not ADMIN_PASSWORD:
        raise HTTPException(400, detail="ADMIN_PASSWORD not set")
    if pwd != ADMIN_PASSWORD:
        raise HTTPException(401, detail="Wrong password")
    request.session["admin"] = True
    return {"ok": True}

@app.post("/admin/logout")
async def admin_logout(request: Request):
    request.session.pop("admin", None)
    return {"ok": True}

@app.get("/admin/stats")
def admin_stats(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(401, detail="Not admin")
    db = get_db()
    try:
        users_count = db.query(User).count()
        logins_count = db.query(LoginEvent).count()
        msgs_count = db.query(ChatMessage).count()

        # last 30 logins
        last_logins = (
            db.query(LoginEvent, User)
            .join(User, User.id == LoginEvent.user_id)
            .order_by(LoginEvent.created_at.desc())
            .limit(30)
            .all()
        )
        items = []
        for ev, u in last_logins:
            items.append({
                "at": ev.created_at.isoformat() if ev.created_at else None,
                "provider": u.provider,
                "email": u.email,
                "name": u.name,
                "ip": ev.ip,
            })

        return {
            "users": users_count,
            "logins": logins_count,
            "messages": msgs_count,
            "last_logins": items,
        }
    finally:
        db.close()

# ----------------------------
# API: user + chat + history + pin
# ----------------------------
@app.get("/api/me")
def api_me(request: Request):
    u = get_current_user(request)
    return {"user": u}

@app.get("/api/history")
def api_history(request: Request, limit: int = 50):
    u = require_user(request)
    db = get_db()
    try:
        msgs = (
            db.query(ChatMessage)
            .filter(ChatMessage.user_id == u["id"])
            .order_by(ChatMessage.created_at.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )
        msgs = list(reversed(msgs))
        pins = (
            db.query(PinnedMessage)
            .filter(PinnedMessage.user_id == u["id"])
            .all()
        )
        pinned_ids = {p.message_id for p in pins}
        return {
            "messages": [
                {
                    "id": m.id,
                    "role": m.role,
                    "content": m.content,
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                    "pinned": m.id in pinned_ids,
                }
                for m in msgs
            ]
        }
    finally:
        db.close()

@app.post("/api/pin")
async def api_pin(request: Request):
    u = require_user(request)
    data = await request.json()
    message_id = int(data.get("message_id", 0))
    if not message_id:
        raise HTTPException(400, detail="message_id required")

    db = get_db()
    try:
        exists = (
            db.query(PinnedMessage)
            .filter(PinnedMessage.user_id == u["id"], PinnedMessage.message_id == message_id)
            .first()
        )
        if exists:
            return {"ok": True}

        # ensure message belongs to user
        msg = db.query(ChatMessage).filter(ChatMessage.id == message_id, ChatMessage.user_id == u["id"]).first()
        if not msg:
            raise HTTPException(404, detail="message not found")

        db.add(PinnedMessage(user_id=u["id"], message_id=message_id))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.post("/api/unpin")
async def api_unpin(request: Request):
    u = require_user(request)
    data = await request.json()
    message_id = int(data.get("message_id", 0))
    if not message_id:
        raise HTTPException(400, detail="message_id required")

    db = get_db()
    try:
        db.query(PinnedMessage).filter(
            PinnedMessage.user_id == u["id"], PinnedMessage.message_id == message_id
        ).delete()
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.post("/api/chat")
async def api_chat(request: Request):
    u = require_user(request)
    data = await request.json()
    user_text = (data.get("message") or "").strip()
    if not user_text:
        raise HTTPException(400, detail="message required")

    db = get_db()
    try:
        # store user msg
        um = ChatMessage(user_id=u["id"], role="user", content=user_text)
        db.add(um)
        db.commit()
        db.refresh(um)

        # build context from last N msgs
        last = (
            db.query(ChatMessage)
            .filter(ChatMessage.user_id == u["id"])
            .order_by(ChatMessage.created_at.desc())
            .limit(20)
            .all()
        )
        last = list(reversed(last))

        messages = [{"role": "system", "content": "Sen Berke_AI’sin. Türkçe konuş. Kısa, net, yardımcı ol."}]
        for m in last:
            if m.role in ("user", "assistant"):
                messages.append({"role": m.role, "content": m.content})

        if not client:
            assistant_text = "OPENAI_API_KEY ayarlı değil."
        else:
            try:
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages,
                    temperature=0.6,
                )
                assistant_text = resp.choices[0].message.content or ""
            except Exception as e:
                assistant_text = f"AI hata: {str(e)}"

        am = ChatMessage(user_id=u["id"], role="assistant", content=assistant_text)
        db.add(am)
        db.commit()
        db.refresh(am)

        return {
            "assistant": assistant_text,
            "user_message_id": um.id,
            "assistant_message_id": am.id,
        }
    finally:
        db.close()

# ----------------------------
# Image endpoint (kalsın ama billing olursa hata döner)
# ----------------------------
@app.post("/api/image")
async def api_image(request: Request):
    u = require_user(request)
    data = await request.json()
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(400, detail="prompt required")

    if not client:
        raise HTTPException(400, detail="OPENAI_API_KEY not set")

    try:
        # NOTE: If billing limit reached, OpenAI returns 400; we surface it to UI.
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1024",
        )
        # openai python returns b64_json (depending on model), keep generic:
        b64 = None
        if getattr(img, "data", None) and len(img.data) > 0:
            d0 = img.data[0]
            b64 = getattr(d0, "b64_json", None) or getattr(d0, "b64", None)
        if not b64:
            raise HTTPException(500, detail="Image returned no data")
        return {"b64": b64}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Görsel üretim hata: {str(e)}")
