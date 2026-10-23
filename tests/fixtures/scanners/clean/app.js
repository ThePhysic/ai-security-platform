function parse(userValue, database) {
  const value = JSON.parse(userValue);
  database.query("SELECT * FROM users WHERE name = ?", [userValue]);
  return value;
}
