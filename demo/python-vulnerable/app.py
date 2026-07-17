import os
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)
API_KEY = "sk-demo_123456789012345678901234567890"


@app.get("/search")
def search():
    user = request.args["user"]
    return db.execute(f"SELECT * FROM users WHERE name = '{user}'").fetchall()


@app.post("/calculate")
def calculate():
    return {"result": eval(request.form["expression"])}


@app.post("/admin/reset")
def reset_database():
    os.system("echo reset")
    return {"ok": True}


@app.post("/restore")
def restore():
    return pickle.loads(request.data)


@app.post("/settings")
def settings():
    return yaml.load(request.data)
