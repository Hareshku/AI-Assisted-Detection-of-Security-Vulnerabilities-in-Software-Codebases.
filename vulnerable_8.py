# vulnerable_8.py
import os

def remove_file():
    print("This function removes a file!")
    filename = input("Enter filename to delete: ")
    os.remove(filename)  # No validation before deletion

if __name__ == "__main__":
    remove_file()
