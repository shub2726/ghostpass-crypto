import sqlite3
from argon2 import PasswordHasher

DB_FILE = "users.db"
ph = PasswordHasher()  # Argon2 password hasher instance

def init_db():
    """Initialize database and create table if not exists."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            Aadhar_uploaded INTEGER,
            DL_uploaded INTEGER       
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            aadhar_filename TEXT,
            DL_filename TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def store_user(username, password):
    """Store user credentials securely using Argon2."""
    password_hash = ph.hash(password)  # Hash password using Argon2
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, Aadhar_uploaded, DL_uploaded) VALUES (?, ?, ?, ?)", (username, password_hash, 0, 0))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

def update_document_status(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    ### Insert into another table as well
    try:
        cursor.execute("UPDATE users SET Aadhar_uploaded = 1, DL_uploaded = 1 WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    """Verify if the username and password match."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result[0]
        try:
            return ph.verify(stored_hash, password)  # Verify password with Argon2
        except:
            return False  # Password mismatch
    return False  # Username not found

def user_exists(username):
    """Check if a user exists."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    exists = cursor.fetchone()
    conn.close()
    return exists

# Initialize database when script is run
if __name__ == "__main__":
    init_db()
    print("[DB] Database initialized.")
