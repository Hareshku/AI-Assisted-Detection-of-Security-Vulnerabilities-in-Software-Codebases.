# vulnerable_7.py
def insecure_function():
    print("Warning: This function evaluates user input!")
    user_input = input("Enter an expression: ")
    return eval(user_input)  # Dangerous eval usage

if __name__ == "__main__":
    result = insecure_function()
    print("Result:", result)
