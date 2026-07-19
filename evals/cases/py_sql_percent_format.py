def lookup(db, request):
    user_id = request.query_params["id"]
    statement = "SELECT * FROM users WHERE id = %s" % user_id
    return db.execute(statement)
