import os
import base64
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# OpenAI (new SDK)
from openai import OpenAI

APP_TITLE = "Berke AI"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

client = None
if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title=APP_TITLE)

# Serve static
app.mount("/static", StaticFiles(directory="static"), name="static")


class ChatReq(BaseModel):
    message: str
    user: Optional[str] = None


class ImgReq(BaseModel):
    prompt: str


@app.get("/", response_class=HTMLResponse)
def home():
    # serve the UI
    index_path = os.path.join("static", "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h3>static/index.html bulunamadı</h3>", status_code=500)
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/health")
def health():
    return {
        "ok": True,
        "openai_key": bool(OPENAI_API_KEY),
        "chat_route": True,
        "image_route": True
    }


@app.post("/chat")
def chat(req: ChatReq):
    if not client:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY ayarlı değil (Render env'e ekle).")

    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="message boş olamaz")

    try:
        # You can switch model if you want
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Samimi, kısa ve yardımcı bir arkadaş gibi konuş. Küfür etme."},
                {"role": "user", "content": msg},
            ],
            temperature=0.7,
        )
        reply = resp.choices[0].message.content or ""
        return {"reply": reply}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat hata: {e}")


@app.post("/image")
def image(req: ImgReq):
    if not client:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY ayarlı değil (Render env'e ekle).")

    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt boş olamaz")

    try:
        # Generate image (base64)
        # If your account supports it, this works. Otherwise we return a readable error.
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1024",
        )

        # Prefer base64 if present
        if img.data and getattr(img.data[0], "b64_json", None):
            return {"b64": img.data[0].b64_json}

        # Or URL if present
        if img.data and getattr(img.data[0], "url", None):
            return {"url": img.data[0].url}

        raise HTTPException(status_code=500, detail="Görsel üretildi ama veri dönmedi.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Görsel hata: {e}")
