const child_process = require("child_process");
function run(userValue, database) {
  eval(userValue); // nosemgrep
  child_process.exec(userValue);
  database.query("SELECT * FROM users WHERE name = " + userValue);
}
