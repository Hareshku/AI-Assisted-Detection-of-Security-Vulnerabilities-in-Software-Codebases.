# secure_7.py
import os
import shutil

def safe_remove():
    print("Secure file removal.")
    filename = input("Enter filename to delete: ")
    if os.path.exists(filename) and filename.endswith(".txt"):
        os.remove(filename)
        print("File deleted securely.")
    else:
        print("Invalid file or does not exist.")

if __name__ == "__main__":
    safe_remove()
