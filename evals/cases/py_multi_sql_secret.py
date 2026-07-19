SERVICE_TOKEN = "fake_token_value_1234567890"


def lookup(db, request):
    account = request.query_params["account"]
    return db.execute(f"SELECT * FROM accounts WHERE id='{account}'")
