import os
import json
import time
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from starlette.middleware.sessions import SessionMiddleware

# Google OAuth (Authlib)
from authlib.integrations.starlette_client import OAuth, OAuthError

# OpenAI SDK
from openai import OpenAI


# =========================
# Paths / Storage
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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "").strip()  # e.g. https://xxx.onrender.com/auth/google/callback

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me").strip()

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "berkekarakulak@gmail.com").strip().lower()
ADMIN_PANEL_KEY = os.getenv("ADMIN_PANEL_KEY", "change-admin-key").strip()


# =========================
# App init
# =========================
app = FastAPI(title="Berke-AI")

# Required for OAuth state/session
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,   # Render is HTTPS
    max_age=60 * 30,   # 30 min (login akışı için yeterli)
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# =========================
# OAuth init
# =========================
oauth = OAuth()

# Google OAuth registration
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid email profile",
        },
    )

# =========================
# OpenAI init
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
    path.parent.mkdir(exist_ok=True, parents=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def get_stats() -> dict:
    stats = load_json(STATS_PATH, default={"guest_total": 0, "google_users": {}})
    if "guest_total" not in stats:
        stats["guest_total"] = 0
    if "google_users" not in stats:
        stats["google_users"] = {}
    return stats

def inc_guest() -> None:
    stats = get_stats()
    stats["guest_total"] += 1
    save_json(STATS_PATH, stats)

def inc_google_user(email: str) -> None:
    stats = get_stats()
    email = (email or "").strip().lower()
    if not email:
        return
    users = stats.get("google_users", {})
    users[email] = int(users.get(email, 0)) + 1
    stats["google_users"] = users
    save_json(STATS_PATH, stats)

def read_persona() -> str:
    p = BASE_DIR / "persona.txt"
    if p.exists():
        try:
            return p.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    # default persona
    return (
        "Sen Berke-AI'sin. Samimi, dost canlısı, kısa ve net cevap ver. "
        "Kullanıcıya 'kanka/dostum' gibi sıcak bir üslup kullanabilirsin ama abartma. "
        "Gereksiz uzun uzatma, yardımcı ve pratik ol."
    )

PERSONA = read_persona()


def get_or_create_user_id(key: str) -> str:
    """
    key: email (google) veya guest_id
    """
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
    path = mem_path(user_id)
    return load_json(path, default={"user_id": user_id, "created_at": now_ts(), "messages": []})

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
    msgs = mem.get("messages", [])
    out = []
    for m in msgs:
        if "role" in m and "content" in m:
            out.append({"role": m["role"], "content": m["content"]})
    return out


# =========================
# Models
# =========================
class ChatReq(BaseModel):
    message: str
    email: Optional[str] = ""       # google email
    guest_id: Optional[str] = ""    # guest id


class ImageReq(BaseModel):
    prompt: str
    email: Optional[str] = ""
    guest_id: Optional[str] = ""


# =========================
# Routes: UI
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    # index UI
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h2>static/index.html bulunamadı</h2>", status_code=500)
    return FileResponse(index_path)

@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(email: str = "", key: str = ""):
    email = (email or "").strip().lower()
    if email != ADMIN_EMAIL or key != ADMIN_PANEL_KEY:
        return JSONResponse({"detail": "403 Yetkisiz"}, status_code=403)

    admin_path = STATIC_DIR / "admin.html"
    if not admin_path.exists():
        # basit fallback admin html
        return HTMLResponse("<h2>admin.html bulunamadı (static/admin.html)</h2>", status_code=500)

    return FileResponse(admin_path)

@app.get("/admin-data")
def admin_data(email: str = "", key: str = ""):
    email = (email or "").strip().lower()
    if email != ADMIN_EMAIL or key != ADMIN_PANEL_KEY:
        raise HTTPException(status_code=403, detail="Yetkisiz")

    stats = get_stats()
    google_users = stats.get("google_users", {})
    guest_total = stats.get("guest_total", 0)

    # sıralı liste
    users_sorted = sorted(
        [{"email": k, "count": int(v)} for k, v in google_users.items()],
        key=lambda x: x["count"],
        reverse=True,
    )
    return {"guest_total": guest_total, "google_users": users_sorted}


# =========================
# Routes: Guest
# =========================
@app.post("/guest")
def guest():
    inc_guest()
    return {"ok": True, "guest_total": get_stats().get("guest_total", 0)}


# =========================
# Routes: Google OAuth
# =========================
@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        raise HTTPException(
            status_code=500,
            detail="Google OAuth ENV eksik: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI",
        )

    redirect_uri = GOOGLE_REDIRECT_URI

    # "prompt=select_account" -> her seferinde hesap seçtirir
    # (Google bazen cookie ile yine otomatik geçebilir ama çoğu durumda sorar)
    return await oauth.google.authorize_redirect(
        request,
        redirect_uri,
        prompt="select_account",
        access_type="online",
    )

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=f"OAuth error: {str(e)}")

    # OpenID Connect userinfo
    userinfo = token.get("userinfo")
    if not userinfo:
        # fallback
        try:
            userinfo = await oauth.google.userinfo(token=token)
        except Exception:
            userinfo = {}

    email = (userinfo.get("email") or "").strip().lower()

    if not email:
        raise HTTPException(status_code=400, detail="Google email alınamadı")

    # log giriş sayısı
    inc_google_user(email)

    # IMPORTANT: Siteye tekrar gelince tekrar onboarding çıksın istiyorsun.
    # O yüzden cookie/session ile "logged-in" tutmuyoruz.
    # Callback'te direkt query param ile sohbet ekranına yönlendiriyoruz.
    return RedirectResponse(url=f"/?login=google&email={email}")


# =========================
# Routes: Chat
# =========================
@app.post("/chat")
def chat(req: ChatReq):
    if client is None:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY tanımlı değil (Render ENV)")

    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Mesaj boş")

    email = (req.email or "").strip().lower()
    guest_id = (req.guest_id or "").strip()

    # user key -> email varsa email, yoksa guest_id, o da yoksa "guest"
    if email:
        user_key = f"google:{email}"
    elif guest_id:
        user_key = f"guest:{guest_id}"
    else:
        user_key = "guest:anonymous"

    user_id = get_or_create_user_id(user_key)

    # memory'e yaz
    append_message(user_id, "user", msg)

    # context
    ctx = build_context(user_id)

    # System persona + context ile cevap
    # model ismi hesabına göre değişebilir; çalışmazsa log at düzeltelim.
    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {"role": "system", "content": PERSONA},
                *ctx
            ],
        )

        # text extraction
        reply = ""
        # responses API: output_text helper çoğu sürümde var
        if hasattr(response, "output_text") and response.output_text:
            reply = response.output_text
        else:
            # fallback parse
            try:
                for item in response.output:
                    if item.type == "message":
                        for c in item.content:
                            if c.type == "output_text":
                                reply += c.text
            except Exception:
                reply = str(response)

        reply = (reply or "").strip()
        if not reply:
            reply = "Şu an teknik bir sorun var ama buradayım. Tekrar dener misin?"

        append_message(user_id, "assistant", reply)
        return {"reply": reply}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI hata: {str(e)}")


# =========================
# Routes: Image
# =========================
@app.post("/image")
def image(req: ImageReq):
    if client is None:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY tanımlı değil (Render ENV)")

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

    # prompt'u hafızaya ekle (istersen)
    append_message(user_id, "user", f"[IMAGE PROMPT]\n{prompt}")

    # kalite yükseltme (ChatGPT tarzı)
    final_prompt = (
        "Ultra premium, high-quality, cinematic image. "
        "Clean composition, sharp subject, realistic lighting, high detail. "
        "No text, no watermark. "
        f"PROMPT: {prompt}"
    )

    try:
        img = client.images.generate(
            model="gpt-image-1",
            prompt=final_prompt,
            size="1024x1024",
        )

        # SDK bazen url bazen b64_json döndürür
        data0 = img.data[0]
        b64 = getattr(data0, "b64_json", None)
        url = getattr(data0, "url", None)

        append_message(user_id, "assistant", "[IMAGE GENERATED]")

        return {"b64": b64, "url": url}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Görsel üretim hatası: {str(e)}")
