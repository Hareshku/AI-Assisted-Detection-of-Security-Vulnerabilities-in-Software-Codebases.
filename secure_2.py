# secure_2.py
import subprocess

def run_secure_command():
    print("Secure command execution.")
    command = input("Enter safe command (ls, pwd): ")
    allowed_commands = ["ls", "pwd"]
    if command in allowed_commands:
        subprocess.run(command, shell=False)  # Safe subprocess usage
    else:
        print("Command not allowed.")

if __name__ == "__main__":
    run_secure_command()
