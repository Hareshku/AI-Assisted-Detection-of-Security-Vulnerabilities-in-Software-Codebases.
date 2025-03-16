# secure_8.py
import subprocess

def secure_shell():
    print("Executing commands securely.")
    command = input("Enter safe command (ls, whoami): ")
    allowed_commands = ["ls", "whoami"]
    if command in allowed_commands:
        subprocess.run([command], shell=False)
    else:
        print("Command not allowed.")

if __name__ == "__main__":
    secure_shell()
