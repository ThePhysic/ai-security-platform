function lookup(db, user) {
  return db.query("SELECT id FROM users WHERE id=" + user);
}
