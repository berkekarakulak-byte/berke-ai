import os, json, traceback
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import httpx
import openai

print("🔥 APP.PY ÇALIŞIYOR 🔥")

# ================= CONFIG =================
openai.api_key = os.getenv("OPENAI_API_KEY")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

ADMIN_EMAIL = "berkekarakulak@gmail.com"

# ================= APP =================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

os.makedirs("memories", exist_ok=True)

if not os.path.exists("stats.json"):
    with open("stats.json", "w") as f:
        json.dump({"google_users": {}, "guest_count": 0}, f)

# ================= HELPERS =================
def load_stats():
    if not os.path.exists("stats.json"):
        return {"google_users": {}, "guest_count": 0}
    with open("stats.json", "r") as f:
        return json.load(f)

def save_stats(data):
    with open("stats.json", "w") as f:
        json.dump(data, f, indent=2)

def memory_path(email):
    safe = email.replace("@", "_at_").replace(".", "_")
    return f"memories/{safe}.json"

# ================= ROUTES =================
@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

# ---------- GOOGLE LOGIN ----------
@app.get("/auth/google")
def google_login():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid email profile"
        "&prompt=select_account"
    )
    return RedirectResponse(url)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        code = request.query_params.get("code")
        if not code:
            return RedirectResponse("/")

        async with httpx.AsyncClient() as client:
            token = await client.post(
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
            access = token.json().get("access_token")

            userinfo = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access}"},
            )

        info = userinfo.json()
        email = info.get("email")
        name = info.get("name", "")

        stats = load_stats()
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        if email not in stats["google_users"]:
            stats["google_users"][email] = {
                "count": 1,
                "first_login": now,
                "last_login": now,
            }
        else:
            stats["google_users"][email]["count"] += 1
            stats["google_users"][email]["last_login"] = now

        save_stats(stats)

        mem = memory_path(email)
        if not os.path.exists(mem):
            with open(mem, "w") as f:
                json.dump({"name": name, "messages": []}, f, indent=2)

        return RedirectResponse(f"/?login=google&email={email}")

    except Exception:
        print("🔥 GOOGLE CALLBACK ERROR")
        print(traceback.format_exc())
        return RedirectResponse("/")

# ---------- GUEST ----------
@app.post("/guest")
def guest():
    stats = load_stats()
    stats["guest_count"] += 1
    save_stats(stats)
    return {"ok": True}

# ---------- CHAT ----------
@app.post("/chat")
async def chat(req: Request):
    try:
        data = await req.json()
        message = data.get("message")
        email = data.get("email")

        if not message:
            return {"reply": "Bir şey yazman lazım 🙂"}

        history = []
        name = "dostum"

        if email:
            with open(memory_path(email), "r") as f:
                mem = json.load(f)
            name = mem.get("name", name)
            history = mem["messages"][-6:]

        messages = [
            {"role": "system", "content": f"Samimi, dost canlısı bir asistansın. Kullanıcının adı {name}."}
        ] + history + [{"role": "user", "content": message}]

        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages
        )

        reply = completion.choices[0].message["content"]

        if email:
            mem["messages"].append({"role": "user", "content": message})
            mem["messages"].append({"role": "assistant", "content": reply})
            with open(memory_path(email), "w") as f:
                json.dump(mem, f, indent=2)

        return {"reply": reply}

    except Exception:
        print("🔥 CHAT ERROR")
        print(traceback.format_exc())
        return {"reply": "Şu an teknik bir sorun var ama buradayım."}

# ---------- ADMIN ----------
@app.get("/admin", response_class=HTMLResponse)
def admin():
    with open("static/admin.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/admin/data")
def admin_data():
    return load_stats()
