# vulnerable_9.py
def insecure_password_storage():
    print("This function stores passwords in plaintext!")
    password = input("Enter your password: ")
    with open("passwords.txt", "a") as f:
        f.write(password + "\n")  # Storing passwords insecurely
    print("Password saved.")

if __name__ == "__main__":
    insecure_password_storage()
