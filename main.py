
from cryptography.fernet import Fernet
from getpass import getpass
import os, sys, func


# ---- MAIN PROGRAM ----
def main():
    print("Secure Python Journal")

    if not os.path.exists(func.DB_FILE):
        print("Created new encrypted journal database.")
        password = getpass("Defined your password: ")
        func.init_db(Fernet(func.generate_key_from_password(password)))
    else:
        password = getpass("Enter your journal password: ")
    key = func.generate_key_from_password(password)
    fernet = Fernet(key)

    if not func.check_password(fernet):
        print ("❌ Incorrect password.")
        sys.exit()

    while True:
        print("\n1. Add entry")
        print("2. Read entries")
        print("3. Exit")

        choice = input("\nChoose: ")

        if choice == "1":
            func.add_entry(fernet)
        elif choice == "2":
            try:
                func.read_entries(fernet)
            except Exception:
                print("❌ Wrong password or corrupted data.")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
