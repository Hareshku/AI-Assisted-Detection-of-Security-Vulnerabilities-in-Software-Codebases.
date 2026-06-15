# vulnerable_2.py
import subprocess

def run_command():
    print("This will execute any command you input!")
    command = input("Enter command: ")
    subprocess.Popen(command, shell=True)  # Insecure subprocess usage

if __name__ == "__main__":
    run_command()
