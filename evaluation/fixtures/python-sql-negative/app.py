def lookup(db, user):
    return db.execute("SELECT id FROM users WHERE name = ?", (user,))
