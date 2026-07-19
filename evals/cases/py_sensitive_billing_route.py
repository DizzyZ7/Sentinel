from fastapi import FastAPI

app = FastAPI()


@app.post("/billing/reset")
def reset_billing():
    return {"ok": True}
