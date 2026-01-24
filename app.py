import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from authlib.integrations.starlette_client import OAuth, OAuthError

from openai import OpenAI
from pydantic import BaseModel


# -------------------------
# Config
# -------------------------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip() or "dev-secret-change-me"
IS_PROD = bool(os.getenv("RENDER")) or os.getenv("APP_ENV", "").lower() == "production"

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    # local fallback
    DATABASE_URL = "sqlite:///./berke_ai.db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


# -------------------------
# App
# -------------------------
app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=60 * 60 * 24 * 30,   # 30 gün login kalsın
    same_site="lax",
    https_only=IS_PROD,
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------
# OAuth
# -------------------------
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# -------------------------
# Helpers
# -------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def base_url_from_request(request: Request) -> str:
    # Render arkasında https doğru gelsin diye
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}".rstrip("/")


# -------------------------
# DB init
# -------------------------
def db_init():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT,
                created_at TEXT,
                last_login_at TEXT,
                login_count INTEGER DEFAULT 0,
                guest_id TEXT UNIQUE
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                method TEXT,
                created_at TEXT
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                role TEXT,
                content TEXT,
                created_at TEXT,
                is_pinned INTEGER DEFAULT 0
            );
        """))


@app.on_event("startup")
def _startup():
    db_init()


# -------------------------
# DB ops
# -------------------------
def upsert_user_by_email(email: str, name: Optional[str]):
    email_l = (email or "").strip().lower()
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, login_count FROM users WHERE email = :email"), {"email": email_l}).fetchone()
        if row:
            user_id, login_count = row[0], int(row[1] or 0)
            conn.execute(
                text("""
                    UPDATE users
                    SET name = COALESCE(:name, name),
                        last_login_at = :last,
                        login_count = :cnt
                    WHERE id = :id
                """),
                {"name": name, "last": now_iso(), "cnt": login_count + 1, "id": user_id}
            )
            return user_id
        else:
            user_id = str(uuid.uuid4())
            conn.execute(
                text("""
                    INSERT INTO users (id, email, name, created_at, last_login_at, login_count)
                    VALUES (:id, :email, :name, :created, :last, 1)
                """),
                {"id": user_id, "email": email_l, "name": name, "created": now_iso(), "last": now_iso()}
            )
            return user_id


def create_guest():
    guest_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO users (id, guest_id, created_at, last_login_at, login_count)
                VALUES (:id, :guest_id, :created, :last, 1)
            """),
            {"id": user_id, "guest_id": guest_id, "created": now_iso(), "last": now_iso()}
        )
    return user_id, guest_id


def log_login(user_id: str, method: str):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO login_logs (id, user_id, method, created_at)
                VALUES (:id, :uid, :m, :t)
            """),
            {"id": str(uuid.uuid4()), "uid": user_id, "m": method, "t": now_iso()}
        )


def get_user_by_id(user_id: str):
    with engine.begin() as conn:
        row = conn.execute(
            text("""
                SELECT id, email, name, guest_id, login_count, last_login_at
                FROM users WHERE id = :id
            """),
            {"id": user_id}
        ).fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "email": row[1],
            "name": row[2],
            "guest_id": row[3],
            "login_count": int(row[4] or 0),
            "last_login_at": row[5],
        }


def save_message(user_id: str, role: str, content: str) -> str:
    mid = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO messages (id, user_id, role, content, created_at, is_pinned)
                VALUES (:id, :uid, :r, :c, :t, 0)
            """),
            {"id": mid, "uid": user_id, "r": role, "c": content, "t": now_iso()}
        )
    return mid


def recent_messages(user_id: str, limit: int = 20):
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                SELECT id, role, content, created_at, is_pinned
                FROM messages
                WHERE user_id = :uid
                ORDER BY created_at DESC
                LIMIT :lim
            """),
            {"uid": user_id, "lim": limit}
        ).fetchall()
    rows = list(reversed(rows))
    return [
        {"id": r[0], "role": r[1], "content": r[2], "created_at": r[3], "is_pinned": bool(r[4])}
        for r in rows
    ]


def toggle_pin(user_id: str, message_id: str, pinned: bool):
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE messages
                SET is_pinned = :p
                WHERE id = :mid AND user_id = :uid
            """),
            {"p": 1 if pinned else 0, "mid": message_id, "uid": user_id}
        )


# -------------------------
# Routes
# -------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=403, detail="Yetkisiz (login gerekli).")
    user = get_user_by_id(uid)
    if not user:
        raise HTTPException(status_code=403, detail="Yetkisiz.")
    if (user.get("email") or "").lower() != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Yetkisiz (admin değil).")

    with open("static/admin.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/admin/data")
def admin_data(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=403, detail="Yetkisiz.")
    user = get_user_by_id(uid)
    if not user or (user.get("email") or "").lower() != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Yetkisiz (admin değil).")

    with engine.begin() as conn:
        users = conn.execute(text("""
            SELECT id, email, name, guest_id, login_count, last_login_at, created_at
            FROM users
            ORDER BY last_login_at DESC
            LIMIT 200
        """)).fetchall()

        logs = conn.execute(text("""
            SELECT method, created_at
            FROM login_logs
            ORDER BY created_at DESC
            LIMIT 200
        """)).fetchall()

        guest_count = conn.execute(text("""
            SELECT COUNT(*) FROM users WHERE email IS NULL
        """)).fetchone()[0]

        google_count = conn.execute(text("""
            SELECT COUNT(*) FROM users WHERE email IS NOT NULL
        """)).fetchone()[0]

    return {
        "counts": {"guest_users": int(guest_count), "google_users": int(google_count)},
        "users": [
            {
                "id": u[0],
                "email": u[1],
                "name": u[2],
                "guest_id": u[3],
                "login_count": int(u[4] or 0),
                "last_login_at": u[5],
                "created_at": u[6],
            }
            for u in users
        ],
        "recent_logins": [{"method": l[0], "created_at": l[1]} for l in logs],
    }


@app.get("/me")
def me(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        return {"logged_in": False}

    user = get_user_by_id(uid)
    if not user:
        request.session.clear()
        return {"logged_in": False}

    email = (user.get("email") or "").lower()
    is_admin = bool(email) and (email == ADMIN_EMAIL)

    return {
        "logged_in": True,
        "user_id": user["id"],
        "email": user.get("email"),
        "name": user.get("name"),
        "guest": user.get("email") is None,
        "login_count": user.get("login_count", 0),
        "is_admin": is_admin,
    }


@app.post("/guest")
def guest_login(request: Request):
    user_id, guest_id = create_guest()
    request.session["user_id"] = user_id
    request.session["guest_id"] = guest_id
    log_login(user_id, "guest")
    return {"ok": True}


@app.get("/auth/google")
async def auth_google(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth env eksik (GOOGLE_CLIENT_ID/SECRET).")

    base = base_url_from_request(request)
    redirect_uri = f"{base}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=f"Google OAuth hata: {str(e)}")

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.google.userinfo(token=token)

    email = (userinfo.get("email") or "").strip()
    name = (userinfo.get("name") or "").strip() or None

    if not email:
        raise HTTPException(status_code=400, detail="Google'dan email alınamadı.")

    user_id = upsert_user_by_email(email=email, name=name)
    request.session["user_id"] = user_id
    request.session.pop("guest_id", None)

    log_login(user_id, "google")

    return RedirectResponse(url="/", status_code=302)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# -------------------------
# Chat + Pin
# -------------------------
class ChatReq(BaseModel):
    message: str

class PinReq(BaseModel):
    message_id: str
    pinned: bool

@app.get("/history")
def history(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        return {"messages": []}
    return {"messages": recent_messages(uid, limit=30)}

@app.post("/pin")
def pin(req: PinReq, request: Request):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=403, detail="Login gerekli.")
    toggle_pin(uid, req.message_id, req.pinned)
    return {"ok": True}

@app.post("/chat")
def chat(req: ChatReq, request: Request):
    uid = request.session.get("user_id")

    # login yoksa: kullanıcıya onboarding gösteriyoruz; ama chat endpoint’i yine de cevap verebilir
    if not uid:
        # otomatik misafir yarat (kullanıcı direkt sohbetten yazarsa)
        uid, guest_id = create_guest()
        request.session["user_id"] = uid
        request.session["guest_id"] = guest_id
        log_login(uid, "guest")

    if not client:
        return JSONResponse({"reply": "OpenAI anahtarı yok. Render ENV: OPENAI_API_KEY ekle."})

    user_text = (req.message or "").strip()
    if not user_text:
        return {"reply": "Bir şey yaz kanka 😄"}

    # DB’ye user mesajı yaz
    save_message(uid, "user", user_text)

    # Son 20 mesajı modele bağlam yap
    ctx = recent_messages(uid, limit=20)
    messages = [{"role": "system", "content": "Sen samimi, dost canlısı bir Türkçe asistansın. Kısa ve net konuş. Kullanıcının tonuna uyum sağla."}]
    for m in ctx:
        role = "assistant" if m["role"] == "ai" else m["role"]
        if role not in ("user", "assistant", "system"):
            role = "user"
        messages.append({"role": role, "content": m["content"]})

    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
        )
        reply = r.choices[0].message.content or "…"
    except Exception as e:
        reply = "Şu an teknik bir sorun var ama buradayım."

    # DB’ye ai mesajı yaz
    save_message(uid, "ai", reply)

    return {"reply": reply}
