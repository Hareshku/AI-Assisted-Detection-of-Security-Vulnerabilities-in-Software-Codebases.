# secure_9.py
import json

def safe_json_load():
    print("Loading JSON securely.")
    filename = input("Enter JSON filename: ")
    try:
        with open(filename, "r") as f:
            data = json.load(f)
        print("Loaded JSON data:", data)
    except (json.JSONDecodeError, FileNotFoundError):
        print("Invalid JSON or file not found.")

if __name__ == "__main__":
    safe_json_load()
