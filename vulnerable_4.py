# vulnerable_4.py
def execute_code():
    print("This function executes arbitrary Python code!")
    user_code = input("Enter Python code: ")
    exec(user_code)  # Dangerous use of exec

if __name__ == "__main__":
    execute_code()
