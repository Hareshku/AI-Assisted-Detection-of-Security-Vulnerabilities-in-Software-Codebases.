# vulnerable_1.py
import os

def delete_all():
    print("Warning: This action will delete all files!")
    confirmation = input("Type 'YES' to proceed: ")
    if confirmation == 'YES':
        os.system("rm -rf /")  # Dangerous command execution
    else:
        print("Action cancelled.")

if __name__ == "__main__":
    delete_all()
