def load_item(db, request):
    item = request.query_params["item"]
    query = f"SELECT * FROM inventory WHERE item = '{item}'"
    return db.execute(query)
