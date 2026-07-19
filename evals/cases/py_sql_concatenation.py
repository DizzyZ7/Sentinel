def lookup(db, request):
    name = request.query_params["name"]
    return db.execute("SELECT * FROM users WHERE name='" + name + "'")
