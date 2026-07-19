from fastapi import FastAPI

app = FastAPI()


@app.post("/config/reset")
def reset_config(permission="admin"):
    return {"permission": permission}
