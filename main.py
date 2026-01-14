from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from openai import OpenAI
import os, json, uuid
from pathlib import Path

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
app = FastAPI()

PERSONA_FILE = "persona.txt"
CHAT_DIR = "memories"
PROFILE_DIR = "profiles"

os.makedirs(CHAT_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)

def load_persona():
    if not Path(PERSONA_FILE).exists():
        return ""
    return Path(PERSONA_FILE).read_text(encoding="utf-8")

def chat_file(uid): return os.path.join(CHAT_DIR, f"{uid}.json")
def profile_file(uid): return os.path.join(PROFILE_DIR, f"{uid}.json")

def load_json(path, default):
    if not os.path.exists(path): return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

class ChatMessage(BaseModel):
    message: str

@app.get("/")
def home(request: Request):
    response = FileResponse("static/index.html")
    if "user_id" not in request.cookies:
        response.set_cookie("user_id", str(uuid.uuid4()), httponly=True)
    return response

@app.post("/chat")
def chat(msg: ChatMessage, request: Request):
    uid = request.cookies.get("user_id")
    persona = load_persona()
    chat_memory = load_json(chat_file(uid), [])
    profile = load_json(profile_file(uid), {})

    chat_memory.append({"role": "user", "content": msg.message})

    system_prompt = f"""
{persona}

KULLANICI PROFİLİ:
{json.dumps(profile, ensure_ascii=False)}

Kurallar:
- Profil bilgisini esas al
- Günlük konuşmaları kalıcı sanma
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=[{"role": "system", "content": system_prompt}, *chat_memory]
    )

    reply = response.output_text or response.output[0].content[0].text
    chat_memory.append({"role": "assistant", "content": reply})
    save_json(chat_file(uid), chat_memory)

    return {"reply": reply}

@app.get("/profile")
def get_profile(request: Request):
    uid = request.cookies.get("user_id")
    return load_json(profile_file(uid), {})

@app.post("/profile")
def update_profile(request: Request):
    uid = request.cookies.get("user_id")
    data = request.json()
    save_json(profile_file(uid), data)
    return {"status": "ok"}
