from fastapi import FastAPI

app = FastAPI()


@app.delete("/admin/users")
def delete_user():
    return {"deleted": True}
