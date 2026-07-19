function lookup(db, req) {
  return db.query("SELECT * FROM users WHERE id=?", [req.params.id]);
}
