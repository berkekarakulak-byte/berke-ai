import os
import json
import traceback
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from openai import OpenAI

BUILD = "2026-01-19_ULTRA_GLASS_01"
print(f"🔥 BUILD: {BUILD} 🔥")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")

ADMIN_EMAIL = "berkekarakulak@gmail.com"

client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

MEM_DIR = Path("memories")
MEM_DIR.mkdir(exist_ok=True)

STATS_PATH = Path("stats.json")
if not STATS_PATH.exists():
    STATS_PATH.write_text(json.dumps({"google_users": {}, "guest_count": 0}, indent=2), encoding="utf-8")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_stats():
    return json.loads(STATS_PATH.read_text(encoding="utf-8"))


def save_stats(d):
    STATS_PATH.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_email_to_filename(email: str) -> Path:
    safe = email.replace("@", "_at_").replace(".", "_")
    return MEM_DIR / f"{safe}.json"


def ensure_user_memory(email: str, name: str):
    p = safe_email_to_filename(email)
    if not p.exists():
        p.write_text(json.dumps({"name": name or "", "messages": []}, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def load_user_memory(email: str):
    p = safe_email_to_filename(email)
    if not p.exists():
        return {"name": "", "messages": []}
    return json.loads(p.read_text(encoding="utf-8"))


def save_user_memory(email: str, mem: dict):
    p = safe_email_to_filename(email)
    p.write_text(json.dumps(mem, indent=2, ensure_ascii=False), encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def home():
    return Path("static/index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {
        "build": BUILD,
        "OPENAI_API_KEY_set": bool(OPENAI_API_KEY),
        "GOOGLE_CLIENT_ID_set": bool(GOOGLE_CLIENT_ID),
        "GOOGLE_CLIENT_SECRET_set": bool(GOOGLE_CLIENT_SECRET),
        "GOOGLE_REDIRECT_URI_set": bool(GOOGLE_REDIRECT_URI),
    }


@app.post("/guest")
def guest():
    stats = load_stats()
    stats["guest_count"] = int(stats.get("guest_count", 0)) + 1
    save_stats(stats)
    return {"ok": True}


@app.get("/auth/google")
def auth_google():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        "&prompt=select_account"
    )
    return RedirectResponse(url)


@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        code = request.query_params.get("code")
        if not code:
            return RedirectResponse("/?err=no_code")

        async with httpx.AsyncClient(timeout=20) as c:
            token_res = await c.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_json = token_res.json()
            access_token = token_json.get("access_token")
            if not access_token:
                return RedirectResponse("/?err=token")

            userinfo_res = await c.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            info = userinfo_res.json()

        email = info.get("email", "")
        name = info.get("name", "")

        if not email:
            return RedirectResponse("/?err=no_email")

        stats = load_stats()
        users = stats.setdefault("google_users", {})
        u = users.get(email)

        t = now_str()
        if not u:
            users[email] = {"count": 1, "first_login": t, "last_login": t}
        else:
            u["count"] = int(u.get("count", 0)) + 1
            u["last_login"] = t

        save_stats(stats)
        ensure_user_memory(email, name)

        return RedirectResponse(f"/?login=google&email={email}")

    except Exception:
        print("🔥 GOOGLE CALLBACK ERROR")
        print(traceback.format_exc())
        return RedirectResponse("/?err=google_exception")


@app.post("/chat")
async def chat(req: Request):
    try:
        data = await req.json()
        message = (data.get("message") or "").strip()
        email = (data.get("email") or "").strip()

        if not message:
            return {"reply": "Bir şey yazman lazım 🙂"}

        history = []
        name = "dostum"
        if email:
            mem = load_user_memory(email)
            name = mem.get("name") or "dostum"
            history = mem.get("messages", [])[-10:]

        system = (
            "Sen samimi, dost canlısı, kısa ve net cevap veren bir asistansın. "
            "Gereksiz uzatma. Ton: arkadaş gibi ama saygılı. "
            f"Kullanıcının adı: {name}."
        )

        messages = [{"role": "system", "content": system}]
        messages += history
        messages.append({"role": "user", "content": message})

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
        )

        reply = resp.choices[0].message.content or ""

        if email:
            mem = load_user_memory(email)
            mem.setdefault("messages", [])
            mem["messages"].append({"role": "user", "content": message})
            mem["messages"].append({"role": "assistant", "content": reply})
            if len(mem["messages"]) > 200:
                mem["messages"] = mem["messages"][-200:]
            save_user_memory(email, mem)

        return {"reply": reply}

    except Exception:
        print("🔥 CHAT ERROR")
        print(traceback.format_exc())
        return {"reply": "Şu an teknik bir sorun var ama buradayım."}


@app.get("/admin", response_class=HTMLResponse)
def admin_ui(request: Request):
    email = request.query_params.get("email")
    if email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Yetkisiz")
    return Path("static/admin.html").read_text(encoding="utf-8")


@app.get("/admin/data")
def admin_data(request: Request):
    email = request.query_params.get("email")
    if email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Yetkisiz")
    return load_stats()
