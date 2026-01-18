from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from datetime import datetime
import os, json, uuid
import httpx
from openai import OpenAI

# ================= CONFIG =================
APP_NAME = "Berke AI"
ADMIN_EMAIL = "berkekarakulak@gmail.com"

BASE_DIR = os.path.dirname(__file__)
MEMORY_DIR = os.path.join(BASE_DIR, "memories")
STATIC_DIR = os.path.join(BASE_DIR, "static")
USERS_FILE = os.path.join(BASE_DIR, "users.json")

os.makedirs(MEMORY_DIR, exist_ok=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

client = OpenAI(api_key=OPENAI_API_KEY)

PERSONA = (
    "Samimi, dost canlısı, kısa ama anlamlı cevaplar veren, "
    "insanı motive eden bir yapay zekasın."
)

app = FastAPI()


# ================= MODELS =================
class ChatIn(BaseModel):
    message: str


# ================= HELPERS =================
def memory_path(uid):
    return os.path.join(MEMORY_DIR, f"{uid}.json")


def load_memory(uid):
    if not uid:
        return []
    path = memory_path(uid)
    if not os.path.exists(path):
        return []
    return json.load(open(path, encoding="utf-8"))


def save_memory(uid, memory):
    if not uid:
        return
    json.dump(
        memory[-20:],
        open(memory_path(uid), "w", encoding="utf-8"),
        ensure_ascii=False,
        indent=2,
    )


def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    return json.load(open(USERS_FILE, encoding="utf-8"))


def save_user(email):
    users = load_users()
    if email not in [u["email"] for u in users]:
        users.append(
            {
                "email": email,
                "first_login": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }
        )
        json.dump(
            users,
            open(USERS_FILE, "w", encoding="utf-8"),
            ensure_ascii=False,
            indent=2,
        )


# ================= ROUTES =================
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    html = open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8").read()
    resp = HTMLResponse(html)

    if not request.cookies.get("uid"):
        resp.set_cookie(
            "uid", str(uuid.uuid4()), max_age=60 * 60 * 24 * 365
        )

    return resp


@app.post("/chat")
def chat(data: ChatIn, request: Request):
    uid = request.cookies.get("uid")
    memory = load_memory(uid)

    memory.append({"role": "user", "content": data.message})

    messages = [{"role": "system", "content": PERSONA}] + memory[-10:]

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=messages,
    )

    reply = response.output_text

    memory.append({"role": "assistant", "content": reply})
    save_memory(uid, memory)

    return {
        "reply": reply,
        "time": datetime.now().strftime("%H:%M"),
    }


# ================= GOOGLE LOGIN =================
@app.get("/auth/google")
def google_login():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
    )
    return RedirectResponse(url)


@app.get("/auth/google/callback")
async def google_callback(code: str):
    async with httpx.AsyncClient() as http:
        token = (
            await http.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                },
            )
        ).json()

        userinfo = (
            await http.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={
                    "Authorization": f"Bearer {token['access_token']}"
                },
            )
        ).json()

    email = userinfo["email"]
    save_user(email)

    resp = RedirectResponse("/")
    resp.set_cookie("uid", email, max_age=60 * 60 * 24 * 365)
    return resp


# ================= ADMIN =================
@app.get("/admin")
def admin_api(request: Request):
    if request.cookies.get("uid") != ADMIN_EMAIL:
        return JSONResponse({"error": "Yetkisiz"}, status_code=403)
    return load_users()


@app.get("/admin-ui", response_class=HTMLResponse)
def admin_ui(request: Request):
    if request.cookies.get("uid") != ADMIN_EMAIL:
        return HTMLResponse("<h2>403 Yetkisiz</h2>", status_code=403)

    return open(os.path.join(STATIC_DIR, "admin.html"), encoding="utf-8").read()
