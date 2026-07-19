VERSION = "1"


def run(db, user):
    query = f"SELECT * FROM users WHERE name={user}"
    return db.execute(query)
