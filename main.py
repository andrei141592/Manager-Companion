
from cryptography.fernet import Fernet
from getpass import getpass
import os, sys, func


# ---- MAIN PROGRAM ----
def main():
    print("Secure Python Journal")

    if not os.path.exists(func.DB_FILE):
        print("Created new encrypted journal database.")
        password = getpass("Defined your password: ")
        func.init_db(password)
    else:
        password = getpass("Enter your journal password: ")

    if not func.check_password(password):
        print ("❌ Incorrect password.")
        sys.exit()

    while True:
        print("\n1. Add entry")
        print("2. Read entries")
        print("3. Change password")
        print("4. Exit")

        choice = input("\nChoose: ")

        if choice == "1":
            entry = input("Write your journal entry:\n> ")
            func.add_entry(password, entry)
        elif choice == "2":
            print (func.read_entry(password))
        elif choice == "3":
            current_password = getpass("Enter your curent password: ")

            if not func.check_password(current_password):
                print ("❌ Incorrect password.")
                sys.exit()
            
            new_password = getpass("Defined your password: ")
            func.change_password(current_password, new_password)

            print("Pasword changed succesfuly")
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")



if __name__ == "__main__":
    main()
