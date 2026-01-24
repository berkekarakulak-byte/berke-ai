import os
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from starlette.middleware.sessions import SessionMiddleware  # ✅ MUST
from authlib.integrations.starlette_client import OAuth, OAuthError

from openai import OpenAI


# ----------------------------
# Config
# ----------------------------
ADMIN_EMAIL = "berkekarakulak@gmail.com"

BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
MEMORIES_DIR = BASE_DIR / "memories"

DATA_DIR.mkdir(exist_ok=True)
MEMORIES_DIR.mkdir(exist_ok=True)

ANALYTICS_PATH = DATA_DIR / "analytics.json"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")  # https://.../auth/google/callback

ADMIN_PANEL_KEY = os.getenv("ADMIN_PANEL_KEY", "")

# ✅ session secret
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    SESSION_SECRET = "dev-session-secret-change-me"


# ----------------------------
# Helpers
# ----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_user_id(email: str) -> str:
    h = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:24]
    return f"u_{h}"

def load_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(path: Path, data: Any):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def load_analytics() -> Dict[str, Any]:
    return load_json(ANALYTICS_PATH, {"guests_total": 0, "users": {}})

def bump_guest():
    a = load_analytics()
    a["guests_total"] = int(a.get("guests_total", 0)) + 1
    save_json(ANALYTICS_PATH, a)

def bump_user_login(email: str):
    a = load_analytics()
    users = a.setdefault("users", {})
    u = users.setdefault(email, {"logins": 0, "first_login": now_iso(), "last_login": now_iso()})
    u["logins"] = int(u.get("logins", 0)) + 1
    u["last_login"] = now_iso()
    users[email] = u
    a["users"] = users
    save_json(ANALYTICS_PATH, a)

def require_admin(email: str, key: str):
    if email.strip().lower() != ADMIN_EMAIL.lower():
        raise HTTPException(status_code=403, detail="Yetkisiz (admin email değil).")
    if ADMIN_PANEL_KEY and key != ADMIN_PANEL_KEY:
        raise HTTPException(status_code=403, detail="Yetkisiz (admin key yanlış).")

def memory_path_for_email(email: str) -> Path:
    uid = safe_user_id(email)
    return MEMORIES_DIR / f"{uid}.json"

def load_history(email: str) -> List[Dict[str, str]]:
    p = memory_path_for_email(email)
    data = load_json(p, {"messages": []})
    msgs = data.get("messages", [])
    if not isinstance(msgs, list):
        return []
    return msgs[-40:]

def save_history(email: str, messages: List[Dict[str, str]]):
    p = memory_path_for_email(email)
    save_json(p, {"email": email, "updated_at": now_iso(), "messages": messages[-40:]})

def system_persona() -> str:
    return (
        "Sen samimi, cana yakın, kısa ve net konuşan bir asistansın. "
        "Kullanıcıyla 'kanka/bro' vibeında konuşabilirsin ama saygılı ol. "
        "Gereksiz uzatma, pratik öneriler ver."
    )


# ----------------------------
# App
# ----------------------------
app = FastAPI()

# ✅ If this middleware is active, request.session will work
# NOTE: https_only=False to avoid local/test issues. Render already HTTPS.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,
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


class ChatIn(BaseModel):
    message: str
    email: Optional[str] = ""


@app.get("/health")
def health(request: Request):
    # ✅ This will prove whether SessionMiddleware is active
    session_ok = "session" in request.scope
    return {
        "ok": True,
        "session_ok": session_ok,
        "has_google_env": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI),
        "running_file": str(__file__),
    }


@app.get("/")
def home():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h2>static/index.html yok</h2>", status_code=500)
    return FileResponse(index_path)


@app.post("/guest")
def guest():
    bump_guest()
    return {"ok": True}


@app.get("/auth/google")
async def auth_google(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        raise HTTPException(status_code=500, detail="Google env eksik: GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI")
    try:
        return await oauth.google.authorize_redirect(request, GOOGLE_REDIRECT_URI)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Google redirect hata: {e}")


@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo")
        if not userinfo:
            userinfo = await oauth.google.userinfo(token=token)

        email = (userinfo.get("email") or "").strip()
        if not email:
            raise HTTPException(status_code=400, detail="Google email alınamadı.")

        bump_user_login(email)

        ts = str(int(time.time()))
        return RedirectResponse(url=f"/?login=google&email={email}&t={ts}", status_code=302)

    except OAuthError as e:
        raise HTTPException(status_code=400, detail=f"OAuthError: {e.error}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Callback hata: {e}")


@app.get("/admin-ui")
def admin_ui(email: str = "", key: str = ""):
    require_admin(email, key)
    admin_path = STATIC_DIR / "admin.html"
    if not admin_path.exists():
        return HTMLResponse("<h2>static/admin.html yok</h2>", status_code=500)
    return FileResponse(admin_path)


@app.get("/admin-data")
def admin_data(email: str = "", key: str = ""):
    require_admin(email, key)
    a = load_analytics()
    users = a.get("users", {})
    sorted_users = sorted(users.items(), key=lambda kv: kv[1].get("logins", 0), reverse=True)
    return {"guests_total": a.get("guests_total", 0), "users": sorted_users}


@app.post("/chat")
def chat(payload: ChatIn):
    text = (payload.message or "").strip()
    if not text:
        return {"reply": "Bir şey yazmadın kanka 😄"}

    if not OPENAI_API_KEY:
        return {"reply": "OPENAI_API_KEY yok. Render Env Vars'a ekleyip deploy etmen lazım."}

    client = OpenAI(api_key=OPENAI_API_KEY)

    email = (payload.email or "").strip()
    use_memory = bool(email)

    messages: List[Dict[str, str]] = [{"role": "system", "content": system_persona()}]
    if use_memory:
        messages.extend(load_history(email))
    messages.append({"role": "user", "content": text})

    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.7,
        )
        reply = resp.choices[0].message.content.strip() if resp.choices else ""
        if not reply:
            reply = "Bir şeyler ters gitti, tekrar dener misin?"

        if use_memory:
            new_hist = (load_history(email) + [{"role": "user", "content": text}, {"role": "assistant", "content": reply}])[-40:]
            save_history(email, new_hist)

        return {"reply": reply}
    except Exception as e:
        return {"reply": f"Şu an teknik bir sorun var ama buradayım. ({e})"}
