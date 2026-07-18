def find_user(db, request):
    name = request.query_params["name"]
    return db.execute("SELECT * FROM users WHERE name = :name", {"name": name})
