# secure_1.py
import os

def safe_delete():
    print("Secure file deletion function.")
    filename = input("Enter filename to delete: ")
    if os.path.exists(filename) and filename.endswith(".txt"):
        os.remove(filename)
        print("File deleted securely.")
    else:
        print("Invalid file or does not exist.")

if __name__ == "__main__":
    safe_delete()
