import sqlite3
import base64
import hashlib
from cryptography.fernet import Fernet
from getpass import getpass


DB_FILE = "journal.db"


# ---- PASSWORD → ENCRYPTION KEY ----
def generate_key_from_password(password: str) -> bytes:
    # Derive a 32-byte key using SHA-256
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


# ---- DATABASE INITIALIZATION ----
def init_db(fernet: Fernet): #Fernet - an instance of the class cryptography.fernet.Fernet
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS journal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_entry BLOB NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER PRIMARY KEY,
            token BLOB NOT NULL
                   )
        """)
    cursor.execute("SELECT token FROM auth WHERE id=1")
    if cursor.fetchone() is None:
        token = fernet.encrypt(b"OK")
        cursor.execute("INSERT INTO auth (id, token) VALUES (1, ?)", (token,))
        print("Created passwork verification token.")
    else:
        print("This shouldn't happen! 1")
    conn.commit()
    conn.close()


# ---- ADD NEW JOURNAL ENTRY ----
def add_entry(fernet: Fernet):
    entry = input("Write your journal entry:\n> ")

    encrypted = fernet.encrypt(entry.encode())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO journal (encrypted_entry) VALUES (?)", (encrypted,))
    conn.commit()
    conn.close()

    print("Entry saved (encrypted).")

def check_password(fernet: Fernet):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT token FROM auth WHERE id=1")
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return False
    token = row[0]

    try:
        decrypted = fernet.decrypt(token)
        return decrypted == b"OK"
    except:
        return False



# ---- READ ALL ENTRIES ----
def read_entries(fernet: Fernet):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, encrypted_entry FROM journal")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No entries yet.")
        return

    print("\n--- YOUR JOURNAL ---")
    for row_id, encrypted_entry in rows:
        decrypted = fernet.decrypt(encrypted_entry).decode()
        print(f"\n[{row_id}]\n{decrypted}")
    print("---------------------\n")

