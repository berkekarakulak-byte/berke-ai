from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"status": "APP.PY CALISIYOR"}

@app.get("/auth/google")
def google_test():
    return {"status": "GOOGLE ROUTE VAR"}
