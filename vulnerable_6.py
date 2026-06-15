# vulnerable_6.py
import os

def execute_user_command():
    print("This function executes user-provided shell commands!")
    user_input = input("Enter shell command: ")
    os.system(user_input)  # Executing untrusted user input

if __name__ == "__main__":
    execute_user_command()
