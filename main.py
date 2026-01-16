from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
from uuid import uuid4
import os, json

from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

MEMORY_DIR = "memories"
os.makedirs(MEMORY_DIR, exist_ok=True)

class ChatIn(BaseModel):
    message: str

# ---------- USER ----------
def get_user_id(request: Request):
    uid = request.cookies.get("user_id")
    if not uid:
        uid = str(uuid4())
    return uid

# ---------- MEMORY ----------
def short_mem_path(uid): return f"{MEMORY_DIR}/{uid}.json"
def summary_path(uid): return f"{MEMORY_DIR}/{uid}_summary.txt"

def load_short(uid):
    if not os.path.exists(short_mem_path(uid)):
        return []
    with open(short_mem_path(uid), "r", encoding="utf-8") as f:
        return json.load(f)

def save_short(uid, mem):
    with open(short_mem_path(uid), "w", encoding="utf-8") as f:
        json.dump(mem[-20:], f, ensure_ascii=False, indent=2)

def load_summary(uid):
    if not os.path.exists(summary_path(uid)):
        return ""
    with open(summary_path(uid), "r", encoding="utf-8") as f:
        return f.read()

def save_summary(uid, text):
    with open(summary_path(uid), "w", encoding="utf-8") as f:
        f.write(text)

def update_summary(uid, short_mem):
    prompt = [
        {
            "role": "system",
            "content": (
                "Aşağıdaki konuşmalardan kullanıcı hakkında "
                "kalıcı ve önemli bilgileri çıkar. "
                "Kısa, net ve maddeler halinde yaz."
            )
        },
        {
            "role": "user",
            "content": json.dumps(short_mem, ensure_ascii=False)
        }
    ]

    res = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    save_summary(uid, res.output_text)

# ---------- ROUTES ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    resp = HTMLResponse(html)
    if not request.cookies.get("user_id"):
        resp.set_cookie("user_id", str(uuid4()), max_age=60*60*24*365)
    return resp

@app.post("/chat")
def chat(data: ChatIn, request: Request):
    uid = get_user_id(request)

    short_mem = load_short(uid)
    summary = load_summary(uid)

    # Kullanıcı mesajı
    short_mem.append({"role": "user", "content": data.message})

    # AI prompt
    messages = []
    if summary:
        messages.append({
            "role": "system",
            "content": f"Kullanıcı hakkında bilinenler:\n{summary}"
        })

    messages += short_mem[-10:]

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=messages
    )

    reply = response.output_text

    short_mem.append({"role": "assistant", "content": reply})
    save_short(uid, short_mem)

    # Her 5 mesajda bir özeti güncelle
    if len(short_mem) % 5 == 0:
        update_summary(uid, short_mem)

    return JSONResponse({
        "reply": reply,
        "time": datetime.now().strftime("%H:%M")
    })
