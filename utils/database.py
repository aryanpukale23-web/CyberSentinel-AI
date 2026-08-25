import sqlite3
import os

# DATABASE PATH
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(BASE_DIR, "database", "database.db")

# SCHEMA PATH
SCHEMA_FILE = os.path.join(
    BASE_DIR,
    "database",
    "schema.sql"
)


def get_db_connection():

    # Make sure database folder exists
    os.makedirs(
        os.path.dirname(DATABASE),
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    # Make sure database folder exists
    os.makedirs(
        os.path.dirname(DATABASE),
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE
    )

    try:

        with open(
            SCHEMA_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            schema = file.read()

        conn.executescript(
            schema
        )

        conn.commit()

    finally:

        conn.close()
