def lookup(db, user):
    return db.execute(f"SELECT id FROM users WHERE name = {user}")
