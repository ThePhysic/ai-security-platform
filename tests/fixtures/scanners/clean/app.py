import json
import subprocess


def run(user_value, database):
    value = json.loads(user_value)
    subprocess.run(["echo", "controlled-inert"], shell=False)
    database.execute("SELECT * FROM users WHERE name = ?", [user_value])
    return value
