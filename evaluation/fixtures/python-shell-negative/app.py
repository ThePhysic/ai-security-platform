import subprocess
def search(user):
    return subprocess.run(["grep", "--", user], shell=False)
