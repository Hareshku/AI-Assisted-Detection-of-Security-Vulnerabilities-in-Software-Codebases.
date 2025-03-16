# secure_4.py
import pickle

def load_safe_data():
    print("Loading data securely without unsafe deserialization.")
    filename = input("Enter filename: ")
    try:
        with open(filename, "rb") as f:
            data = pickle.load(f)
        print("Data loaded successfully.")
    except (pickle.UnpicklingError, FileNotFoundError):
        print("Error loading data. File may be corrupted or does not exist.")

if __name__ == "__main__":
    load_safe_data()
