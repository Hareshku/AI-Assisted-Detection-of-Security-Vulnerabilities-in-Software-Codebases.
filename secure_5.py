# secure_5.py
def safe_eval():
    print("Evaluating expressions safely using literals.")
    import ast
    user_input = input("Enter a mathematical expression: ")
    try:
        result = ast.literal_eval(user_input)
        print("Result:", result)
    except (SyntaxError, ValueError):
        print("Invalid expression.")

if __name__ == "__main__":
    safe_eval()
