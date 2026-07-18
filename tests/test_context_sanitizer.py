from app.services.context_sanitizer import sanitize_context


def test_sanitizer_redacts_common_credentials_without_changing_line_count() -> None:
    context = '''1: OPENAI_API_KEY="sk-proj-abcdefghijklmnop123456"
2: url = "postgresql://sentinel:super-secret-password@db/sentinel"
3: headers = {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz.123456"}
4: safe = "SELECT * FROM users"
'''
    result = sanitize_context(context)

    assert "sk-proj-abcdefghijklmnop123456" not in result.text
    assert "super-secret-password" not in result.text
    assert "abcdefghijklmnopqrstuvwxyz.123456" not in result.text
    assert result.text.count("\n") == context.count("\n")
    assert len(result.redactions) == 3
    assert result.summary["count"] == 3
    assert result.summary["lines"] == [1, 2, 3]
    assert "SELECT * FROM users" in result.text


def test_sanitizer_redacts_multiline_private_key() -> None:
    context = "before\n-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\nafter\n"
    result = sanitize_context(context)

    assert "abc123" not in result.text
    assert "<REDACTED_SECRET_1:PRIVATE_KEY>" in result.text
    assert result.redactions[0].line == 2
