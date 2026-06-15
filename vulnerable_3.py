# vulnerable_3.py
def unsafe_eval():
    print("Warning: This allows arbitrary code execution!")
    user_input = input("Enter Python expression: ")
    result = eval(user_input)  # Dangerous eval usage
    print("Result:", result)

if __name__ == "__main__":
    unsafe_eval()
