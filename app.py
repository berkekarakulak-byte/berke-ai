import os
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError

from openai import OpenAI


# =========================
# Paths
# =========================
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
MEMORIES_DIR = BASE_DIR / "memories"

DATA_DIR.mkdir(exist_ok=True)
MEMORIES_DIR.mkdir(exist_ok=True)

STATS_PATH = DATA_DIR / "stats.json"
MEM_INDEX_PATH = DATA_DIR / "memory_index.json"


# =========================
# ENV
# =========================
OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY") or "").strip()

GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or "").strip()
GOOGLE_CLIENT_SECRET = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()
GOOGLE_REDIRECT_URI = (os.getenv("GOOGLE_REDIRECT_URI") or "").strip()  # https://xxx.onrender.com/auth/google/callback

SESSION_SECRET = (os.getenv("SESSION_SECRET") or "change-me-session-secret").strip()

ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "berkekarakulak@gmail.com").strip().lower()
ADMIN_PANEL_KEY = (os.getenv("ADMIN_PANEL_KEY") or "change-admin-key").strip()


# =========================
# App
# =========================
app = FastAPI(title="Berke-AI")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,   # Render https
    max_age=60 * 30,   # 30 dakika (oauth state için yeter)
)

if not STATIC_DIR.exists():
    raise RuntimeError("static/ klasörü yok. static/index.html ve static/admin.html olmalı.")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


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
# OpenAI
# =========================
client: Optional[OpenAI] = None
if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)


# =========================
# Helpers
# =========================
def now_ts() -> int:
    return int(time.time())

def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def get_stats() -> dict:
    stats = load_json(STATS_PATH, default={"guest_total": 0, "google_users": {}})
    stats.setdefault("guest_total", 0)
    stats.setdefault("google_users", {})
    return stats

def inc_guest() -> None:
    stats = get_stats()
    stats["guest_total"] = int(stats.get("guest_total", 0)) + 1
    save_json(STATS_PATH, stats)

def inc_google_user(email: str) -> None:
    email = (email or "").strip().lower()
    if not email:
        return
    stats = get_stats()
    users = stats.get("google_users", {})
    users[email] = int(users.get(email, 0)) + 1
    stats["google_users"] = users
    save_json(STATS_PATH, stats)

def read_persona() -> str:
    # samimi, dost canlısı
    return (
        "Sen Berke-AI'sin. Samimi, dost canlısı ve pratik cevap ver. "
        "Kullanıcıya gerektiğinde 'kanka' gibi sıcak bir üslup kullanabilirsin ama abartma. "
        "Kısa ve net ol. Yararlı öneriler sun."
    )

PERSONA = read_persona()

def get_or_create_user_id(key: str) -> str:
    idx = load_json(MEM_INDEX_PATH, default={})
    if key in idx:
        return idx[key]
    uid = str(uuid.uuid4())
    idx[key] = uid
    save_json(MEM_INDEX_PATH, idx)
    return uid

def mem_path(user_id: str) -> Path:
    return MEMORIES_DIR / f"{user_id}.json"

def load_memory(user_id: str) -> dict:
    return load_json(mem_path(user_id), default={"user_id": user_id, "created_at": now_ts(), "messages": []})

def save_memory(user_id: str, mem: dict) -> None:
    save_json(mem_path(user_id), mem)

def append_message(user_id: str, role: str, content: str, max_keep: int = 30) -> None:
    mem = load_memory(user_id)
    mem.setdefault("messages", [])
    mem["messages"].append({"role": role, "content": content, "ts": now_ts()})
    mem["messages"] = mem["messages"][-max_keep:]
    save_memory(user_id, mem)

def build_context(user_id: str) -> List[Dict[str, str]]:
    mem = load_memory(user_id)
    out = []
    for m in mem.get("messages", []):
        if isinstance(m, dict) and "role" in m and "content" in m:
            out.append({"role": m["role"], "content": m["content"]})
    return out


# =========================
# Models
# =========================
class ChatReq(BaseModel):
    message: str
    email: Optional[str] = ""
    guest_id: Optional[str] = ""

class ImageReq(BaseModel):
    prompt: str
    email: Optional[str] = ""
    guest_id: Optional[str] = ""


# =========================
# Basic routes
# =========================
@app.get("/health")
def health():
    return {
        "ok": True,
        "openai_key": bool(OPENAI_API_KEY),
        "google_oauth": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI),
        "time": now_ts(),
    }

@app.get("/", response_class=HTMLResponse)
def home():
    p = STATIC_DIR / "index.html"
    return FileResponse(p)

@app.post("/guest")
def guest():
    inc_guest()
    return {"ok": True, "guest_total": get_stats().get("guest_total", 0)}


# =========================
# Admin
# =========================
def is_admin(email: str, key: str) -> bool:
    return (email or "").strip().lower() == ADMIN_EMAIL and (key or "").strip() == ADMIN_PANEL_KEY

@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(email: str = "", key: str = ""):
    if not is_admin(email, key):
        return JSONResponse({"detail": "403 Yetkisiz"}, status_code=403)
    p = STATIC_DIR / "admin.html"
    return FileResponse(p)

@app.get("/admin-data")
def admin_data(email: str = "", key: str = ""):
    if not is_admin(email, key):
        raise HTTPException(status_code=403, detail="Yetkisiz")

    stats = get_stats()
    users = stats.get("google_users", {})
    guest_total = int(stats.get("guest_total", 0))

    users_sorted = sorted(
        [{"email": e, "count": int(c)} for e, c in users.items()],
        key=lambda x: x["count"],
        reverse=True,
    )
    return {"guest_total": guest_total, "google_users": users_sorted}


# =========================
# Google OAuth
# =========================
@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        raise HTTPException(
            status_code=500,
            detail="Google OAuth ENV eksik: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI",
        )

    # her seferinde hesap seçtir
    return await oauth.google.authorize_redirect(
        request,
        GOOGLE_REDIRECT_URI,
        prompt="select_account",
        access_type="online",
    )

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=f"OAuth error: {str(e)}")

    userinfo = token.get("userinfo") or {}
    email = (userinfo.get("email") or "").strip().lower()
    if not email:
        # bazen userinfo boş dönebilir; tekrar çekmeye çalış
        try:
            userinfo = await oauth.google.userinfo(token=token)
            email = (userinfo.get("email") or "").strip().lower()
        except Exception:
            email = ""

    if not email:
        raise HTTPException(status_code=400, detail="Google email alınamadı")

    # giriş sayısı
    inc_google_user(email)

    # login kalıcı olmasın istiyorsun -> session tutmuyoruz
    # callback -> ana sayfaya parametreyle dön, UI chat'i açar
    return RedirectResponse(url=f"/?login=google&email={email}")


# =========================
# Chat
# =========================
@app.post("/chat")
def chat(req: ChatReq):
    if client is None:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY tanımlı değil (Render ENV).")

    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Mesaj boş")

    email = (req.email or "").strip().lower()
    guest_id = (req.guest_id or "").strip()

    if email:
        user_key = f"google:{email}"
    elif guest_id:
        user_key = f"guest:{guest_id}"
    else:
        user_key = "guest:anonymous"

    user_id = get_or_create_user_id(user_key)

    append_message(user_id, "user", msg)
    ctx = build_context(user_id)

    try:
        resp = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {"role": "system", "content": PERSONA},
                *ctx
            ],
        )

        reply = ""
        if getattr(resp, "output_text", None):
            reply = resp.output_text
        else:
            # fallback parse (nadiren gerekir)
            try:
                for item in resp.output:
                    if item.type == "message":
                        for c in item.content:
                            if c.type == "output_text":
                                reply += c.text
            except Exception:
                reply = ""

        reply = (reply or "").strip() or "Şu an teknik bir sorun var ama buradayım. Tekrar dener misin?"
        append_message(user_id, "assistant", reply)
        return {"reply": reply}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI hata: {str(e)}")


# =========================
# Image
# =========================
@app.post("/image")
def image(req: ImageReq):
    if client is None:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY tanımlı değil (Render ENV).")

    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt boş")

    email = (req.email or "").strip().lower()
    guest_id = (req.guest_id or "").strip()

    if email:
        user_key = f"google:{email}"
    elif guest_id:
        user_key = f"guest:{guest_id}"
    else:
        user_key = "guest:anonymous"

    user_id = get_or_create_user_id(user_key)
    append_message(user_id, "user", f"[IMAGE PROMPT]\n{prompt}")

    final_prompt = (
        "Ultra premium, high-quality, cinematic image. "
        "Clean composition, realistic lighting, high detail, sharp subject. "
        "No text, no watermark. "
        f"PROMPT: {prompt}"
    )

    try:
        img = client.images.generate(
            model="gpt-image-1",
            prompt=final_prompt,
            size="1024x1024",
        )
        d0 = img.data[0]
        b64 = getattr(d0, "b64_json", None)
        url = getattr(d0, "url", None)

        append_message(user_id, "assistant", "[IMAGE GENERATED]")
        return {"b64": b64, "url": url}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Görsel üretim hatası: {str(e)}")
