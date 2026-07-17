import sqlite3
from fastapi import FastAPI, Request

app = FastAPI()
JWT_SECRET = "super-secret-demo-value-123456789"
connection = sqlite3.connect("app.db")


@app.get("/users")
async def users(request: Request):
    name = request.query_params["name"]
    return connection.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()


@app.delete("/internal/tokens")
async def delete_tokens():
    connection.execute("DELETE FROM tokens")
    return {"deleted": True}
