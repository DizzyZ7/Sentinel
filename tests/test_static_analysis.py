from pathlib import Path

from app.services.static_analysis import analyze_repository


def analyze_file(tmp_path: Path, name: str, content: str, language: str) -> set[str]:
    source = tmp_path / name
    source.write_text(content, encoding="utf-8")
    findings = analyze_repository(
        tmp_path,
        [{"path": name, "language": language, "size": source.stat().st_size}],
    )
    return {finding.rule_id for finding in findings}


def test_python_rules_detect_candidates(tmp_path: Path) -> None:
    rules = analyze_file(
        tmp_path,
        "app.py",
        '''from flask import request
import pickle


def run(db):
    name = request.args["name"]
    query = f"SELECT * FROM users WHERE name='{name}'"
    db.execute(query)
    return pickle.loads(request.data)
''',
        "python",
    )
    assert "PY_SQL_INTERPOLATION" in rules
    assert "PY_UNSAFE_DESERIALIZATION" in rules


def test_python_taint_rules_detect_command_path_and_ssrf(tmp_path: Path) -> None:
    rules = analyze_file(
        tmp_path,
        "api.py",
        '''import os
import requests
from flask import request, send_file


def handler():
    command = request.args["command"]
    path = request.args["path"]
    url = request.args["url"]
    os.system(command)
    requests.get(url)
    return send_file(path)
''',
        "python",
    )
    assert {"PY_COMMAND_INJECTION", "PY_PATH_TRAVERSAL", "PY_SSRF"} <= rules


def test_javascript_rules_detect_candidates(tmp_path: Path) -> None:
    rules = analyze_file(
        tmp_path,
        "server.js",
        '''db.query(`SELECT * FROM users WHERE id='${req.query.id}'`);
eval(req.body.code);
child_process.exec(req.query.command);
fs.readFile(req.query.path, callback);
fetch(req.query.url);
''',
        "javascript",
    )
    assert {
        "JS_SQL_INTERPOLATION",
        "JS_DYNAMIC_EXECUTION",
        "JS_COMMAND_INJECTION",
        "JS_PATH_TRAVERSAL",
        "JS_SSRF",
    } <= rules
