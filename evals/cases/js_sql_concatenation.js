function lookup(db, req) {
  return db.execute("SELECT * FROM users WHERE id=" + req.params.id);
}
