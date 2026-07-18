def find_user(db, request):
    name = request.query_params["name"]
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)
