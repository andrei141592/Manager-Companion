import sqlite3
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from getpass import getpass


DB_FILE = "journal.db"


# ---- PASSWORD → ENCRYPTION KEY ----
def generate_password_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))



# ---- DATABASE INITIALIZATION ----
def init_db(password: str): #Fernet - an instance of the class cryptography.fernet.Fernet
    
    #Generate an encripted key
    salt = os.urandom(16) #generate 16 random bytes
    password_key = generate_password_key(password.encode(), salt) #generate an encoded password key based on the password defined by the user
    data_key = Fernet.generate_key() #generated a random 32 byte key (one time)
    encrypted_data_key = Fernet(password_key).encrypt(data_key) #encript the data key with the password key

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER PRIMARY KEY,
            salt BLOB,
            encrypted_data_key BLOB
                   )
        """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS journal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_entry BLOB NOT NULL
        )
    """)
    
    cursor.execute("INSERT INTO AUTH (id, salt, encrypted_data_key) VALUES (1, ?, ?)", (salt, encrypted_data_key))
    
    conn.commit()
    conn.close()

def load_data_key(password: str) -> bytes:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, encrypted_data_key from auth WHERE id = 1")
    salt, encrypted_data_key = cursor.fetchone()
    conn.close()

    password_key = generate_password_key(password.encode(), salt)
    return Fernet(password_key).decrypt(encrypted_data_key)

# ---- ADD NEW JOURNAL ENTRY ----
def add_entry(password: str, entry: str):

    data_key = load_data_key(password)
    encrypted_entry = Fernet(data_key).encrypt(entry.encode())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO journal (encrypted_entry) VALUES (?)", (encrypted_entry,))
    conn.commit()
    conn.close()

# ---- ADD NEW JOURNAL ENTRY ----
def read_entry(password: str):
    data_key = load_data_key(password)
    f = Fernet(data_key)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, encrypted_entry FROM journal")
    rows = cursor.fetchall()
    conn.close()
    output = []
    for row_id, encrypted_entry in rows:
        output.append(f.decrypt(encrypted_entry).decode())
    return output

def change_password(old_password: str, new_password: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, encrypted_data_key FROM auth WHERE id = 1")
    salt, encrypted_data_key = cursor.fetchone()

    # decrypt data key with old password
    old_key = generate_password_key(old_password.encode(), salt)
    data_key = Fernet(old_key).decrypt(encrypted_data_key)

    # re-encrypt data key with new password
    new_salt = os.urandom(16)
    new_key = generate_password_key(new_password.encode(), new_salt)
    new_encrypted_data_key = Fernet(new_key).encrypt(data_key)

    cursor.execute(
        "UPDATE auth SET salt = ?, encrypted_data_key = ? WHERE id = 1",
        (new_salt, new_encrypted_data_key)
    )
    conn.commit()
    conn.close()


def check_password(password: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, encrypted_data_key FROM auth WHERE id = 1")
    salt, encrypted_data_key = cursor.fetchone()

    # decrypt data key with old password
    old_key = generate_password_key(password.encode(), salt)
    try:
        data_key = Fernet(old_key).decrypt(encrypted_data_key)
    except:
        return False
    return True
