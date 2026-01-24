import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

APP_TITLE = "Berke AI"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory="static"), name="static")


class ChatReq(BaseModel):
    message: str


class ImgReq(BaseModel):
    prompt: str
    size: str | None = "1024x1024"


def get_client():
    if OpenAI is None:
        raise HTTPException(status_code=500, detail="openai paketi import edilemedi. requirements.txt kontrol et.")
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY ayarlı değil (Render Env'e ekle).")
    try:
        return OpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI client init hata: {e}")


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
        "openai_sdk_imported": bool(OpenAI is not None),
        "openai_key_set": bool(OPENAI_API_KEY),
        "routes": ["/chat", "/image", "/health"],
    }


@app.post("/chat")
def chat(req: ChatReq):
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="message boş olamaz")

    client = get_client()
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

    size = (req.size or "1024x1024").strip()

    client = get_client()
    try:
        # gpt-image-1 genelde base64 döndürür.
        img = client.images.generate(
            model="gpt-image-1",
            prompt=prompt,
            size=size,
        )

        if img.data and getattr(img.data[0], "b64_json", None):
            return {"b64": img.data[0].b64_json, "size": size}

        if img.data and getattr(img.data[0], "url", None):
            return {"url": img.data[0].url, "size": size}

        raise HTTPException(status_code=500, detail="Görsel üretildi ama veri dönmedi.")
    except Exception as e:
        # UI’de net görebilmen için detail'i büyütüyoruz
        raise HTTPException(status_code=500, detail=f"Görsel üretim hata: {e}")
