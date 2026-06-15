# vulnerable_5.py
import pickle

def load_data():
    print("This function loads untrusted serialized data!")
    filename = input("Enter filename: ")
    with open(filename, "rb") as f:
        data = pickle.load(f)  # Insecure deserialization
    print("Data loaded:", data)

if __name__ == "__main__":
    load_data()
