import sqlite3
import os

# Project root = CyberSentinel-AI
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE = os.path.join(DATABASE_DIR, "database.db")
SCHEMA_FILE = os.path.join(DATABASE_DIR, "schema.sql")


def get_db_connection():
    os.makedirs(DATABASE_DIR, exist_ok=True)

    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():
    os.makedirs(DATABASE_DIR, exist_ok=True)

    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    try:
        with open(
            SCHEMA_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            schema = file.read()

        conn.executescript(schema)
        conn.commit()

    finally:
        conn.close()
