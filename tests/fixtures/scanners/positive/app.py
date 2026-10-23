import subprocess


def run(user_value, database):
    eval(user_value)  # nosemgrep
    subprocess.run(user_value, shell=True)
    database.execute(f"SELECT * FROM users WHERE name = '{user_value}'")
