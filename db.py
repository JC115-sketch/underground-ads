# db.py
import sqlite3
import os

DB_FILENAME = "uadb.db"

def get_db():
    db_path = os.path.join(os.path.dirname(__file__), DB_FILENAME)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row["name"] for row in cur.fetchall()]
    return column in cols

def ensure_column(conn, table, column_def):
    """
    Ensure a column exists in table. column_def should be like 'col_name TYPE DEFAULT 0'
    If missing, runs: ALTER TABLE table ADD COLUMN <column_name> <rest>
    """
    cur = conn.cursor()
    parts = column_def.strip().split(None, 1)
    if len(parts) == 0:
        return
    col_name = parts[0]
    if not column_exists(cur, table, col_name):
        # SQLite allows simple ALTER TABLE ADD COLUMN
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
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

    # users table: include about, is_admin, pgp_public_key, pgp_private_key maybe present
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pgp_public_key TEXT,
        pgp_private_key TEXT,
        about TEXT,
        is_admin INTEGER DEFAULT 0
    )
    """)

    # messages table: now includes is_encrypted flag
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad_id INTEGER,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        is_encrypted INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ad_id) REFERENCES ads (id),
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (recipient_id) REFERENCES users (id)
    )
    """)

    # ratings table: include review text
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        rater_id INTEGER NOT NULL,
        rating INTEGER CHECK(rating >= 1 AND rating <= 5),
        review TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (seller_id) REFERENCES users (id),
        FOREIGN KEY (rater_id) REFERENCES users (id)
    )
    """)

    conn.commit()

    # Now ensure older DBs get columns added (non-destructive)
    # Users table possible columns to ensure (idempotent)
    ensure_column(conn, "users", "pgp_public_key TEXT")
    ensure_column(conn, "users", "pgp_private_key TEXT")
    ensure_column(conn, "users", "about TEXT")
    ensure_column(conn, "users", "is_admin INTEGER DEFAULT 0")

    # Messages table columns
    ensure_column(conn, "messages", "is_encrypted INTEGER DEFAULT 0")
    ensure_column(conn, "messages", "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    # Ratings table
    ensure_column(conn, "ratings", "review TEXT")
    ensure_column(conn, "ratings", "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    conn.commit()
    conn.close()

# If run directly, initialize (useful for CLI migration)
if __name__ == "__main__":
    init_db()
    print("DB initialized/updated:", os.path.join(os.path.dirname(__file__), DB_FILENAME))