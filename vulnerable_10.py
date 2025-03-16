# vulnerable_10.py
import hashlib

def hash_password():
    print("This function hashes passwords using weak algorithms!")
    password = input("Enter password: ")
    hashed = hashlib.md5(password.encode()).hexdigest()  # Weak hashing
    print("Hashed password:", hashed)

if __name__ == "__main__":
    hash_password()
