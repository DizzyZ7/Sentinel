from pathlib import Path

from app.services.static_analysis import analyze_repository


def test_python_rules_detect_candidates(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """from flask import request
import pickle


def run(db):
    name = request.args["name"]
    db.execute(f"SELECT * FROM users WHERE name='{name}'")
    return pickle.loads(request.data)
""",
        encoding="utf-8",
    )
    findings = analyze_repository(
        tmp_path,
        [{"path": "app.py", "language": "python", "size": source.stat().st_size}],
    )
    rules = {finding.rule_id for finding in findings}
    assert "PY_SQL_INTERPOLATION" in rules
    assert "PY_UNSAFE_DESERIALIZATION" in rules


def test_javascript_rules_detect_candidates(tmp_path: Path) -> None:
    source = tmp_path / "server.js"
    source.write_text(
        "db.query(`SELECT * FROM users WHERE id='${req.query.id}'`);\neval(req.body.code);\n",
        encoding="utf-8",
    )
    findings = analyze_repository(
        tmp_path,
        [{"path": "server.js", "language": "javascript", "size": source.stat().st_size}],
    )
    rules = {finding.rule_id for finding in findings}
    assert "JS_SQL_INTERPOLATION" in rules
    assert "JS_DYNAMIC_EXECUTION" in rules
