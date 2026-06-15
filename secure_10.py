# secure_10.py
import bcrypt

def secure_password_storage():
    print("Storing passwords securely.")
    password = input("Enter your password: ").encode()
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt)
    print("Securely hashed password:", hashed_password)

if __name__ == "__main__":
    secure_password_storage()
