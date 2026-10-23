const child_process = require("child_process");
function search(user) { return child_process.exec("grep " + user); }
