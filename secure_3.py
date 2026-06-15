# secure_3.py
import hmac
import hashlib

def secure_hash(password):
    print("Hashing password securely.")
    salt = b"secure_salt"
    hashed = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()
    print("Secure Hash:", hashed)

if __name__ == "__main__":
    user_password = input("Enter password: ")
    secure_hash(user_password)
