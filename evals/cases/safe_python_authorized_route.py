from fastapi import Depends, FastAPI

app = FastAPI()


def current_user():
    return {"id": 1}


@app.delete("/admin/users")
def delete_user(user=Depends(current_user)):
    return {"deleted": True, "actor": user["id"]}
