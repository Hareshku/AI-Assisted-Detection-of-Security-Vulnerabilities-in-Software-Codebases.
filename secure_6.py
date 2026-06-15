# secure_6.py
import os

def secure_file_access():
    print("Accessing files securely.")
    filename = input("Enter filename: ")
    allowed_files = ["data.txt", "config.yaml"]
    if filename in allowed_files:
        with open(filename, "r") as f:
            print(f.read())
    else:
        print("Access denied.")

if __name__ == "__main__":
    secure_file_access()
