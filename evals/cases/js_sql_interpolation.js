function findUser(db, req) {
  return db.query(`SELECT * FROM users WHERE id='${req.query.id}'`);
}
