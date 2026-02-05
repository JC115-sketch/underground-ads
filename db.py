import sqlite3
import os

# DB_NAME = "uadb.db"

def get_db():
    db_path = os.path.join(os.path.dirname(__file__), "uadb.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})") # retrieve info of a table's columns returns a set with one row for each column
    cols = [row["name"] for row in cur.fetchall()]
    return column in cols

def ensure_pgp_columns(conn):
    cur = conn.cursor()
    if not column_exists(cur, "users", "pgp_public_key"):
        cur.execute("ALTER TABLE users ADD COLUMN pgp_public_key TEXT")
    if not column_exists(cur, "users", "pgp_private_key_encrypted"):
        cur.execute("ALTER TABLE users ADD COLUMN pgp_private_key_encrypted TEXT")
    if not column_exists(cur, "users", "pgp_key_salt"):
        cur.execute("ALTER TABLE users ADD COLUMN pgp_key_salt TEXT")
    if not column_exists(cur, "users", "pgp_key_nonce"):
        cur.execute("ALTER TABLE users ADD COLUMN pgp_key_nonce TEXT")
    conn.commit()

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # ads table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image TEXT,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # user table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pgp_public_key TEXT,
            pgp_private_key TEXT
        )
    """)

    # messages table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ad_id) REFERENCES ads (id),
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (recipient_id) REFERENCES users (id)
        )
    """)

    # ratings table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            rater_id INTEGER NOT NULL,
            rating INTEGER CHECK(rating >= 1 AND rating <= 5),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES users (id),
            FOREIGN KEY (rater_id) REFERENCES users (id)
        )
    """)
 

    conn.commit()
    ensure_pgp_columns(conn)
    conn.close()