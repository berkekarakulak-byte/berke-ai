import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# OpenAI SDK (optional at runtime; we handle missing key gracefully)
try:
    from openai import OpenAI
except Exception:
    OpenAI = None


APP_TITLE = "Berke AI"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

client = None
if OpenAI is not None and OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title=APP_TITLE)

# Serve /static
app.mount("/static", StaticFiles(directory="static"), name="static")


class ChatReq(BaseModel):
    message: str


class ImgReq(BaseModel):
    prompt: str


@app.get("/", response_class=HTMLResponse)
def home():
    index_path = os.path.join("static", "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse(
            "<h3>static/index.html bulunamadı</h3><p>Repo'da static/index.html var mı kontrol et.</p>",
            status_code=500,
        )
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/health")
def health():
    return {
        "ok": True,
        "openai_sdk": bool(OpenAI is not None),
        "openai_key_set": bool(OPENAI_API_KEY),
        "routes": ["/", "/chat", "/image", "/health"],
    }


@app.post("/chat")
def chat(req: ChatReq):
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="message boş olamaz")

    if client is None:
        # Key yoksa bile app crash olmaz, sadece endpoint hata döner
        raise HTTPException(
            status_code=500,
            detail="OPENAI_API_KEY ayarlı değil veya openai paketi yok. Render Env'e OPENAI_API_KEY ekle.",
        )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Samimi, kısa, dost gibi konuş. Küfür etme."},
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
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt boş olamaz")

    if client is None:
        raise HTTPException(
            status_code=500,
            detail="OPENAI_API_KEY ayarlı değil veya openai paketi yok. Render Env'e OPENAI_API_KEY ekle.",
        )

    try:
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size="1024x1024",
        )

        # Prefer base64
        if img.data and getattr(img.data[0], "b64_json", None):
            return {"b64": img.data[0].b64_json}

        # Or URL (some accounts return this)
        if img.data and getattr(img.data[0], "url", None):
            return {"url": img.data[0].url}

        raise HTTPException(status_code=500, detail="Görsel üretildi ama veri dönmedi.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Görsel hata: {e}")
