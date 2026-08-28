import os
import psycopg
from psycopg.rows import dict_row


# POSTGRESQL DATABASE CONNECTION

def get_db_connection():

    database_url = os.environ.get("DATABASE_URL")

    if not database_url:

        raise RuntimeError(
            "DATABASE_URL environment variable is not configured."
        )

    conn = psycopg.connect(
        database_url,
        row_factory=dict_row
    )

    return conn


# INITIALIZE DATABASE

def init_db():

    base_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    schema_file = os.path.join(
        base_dir,
        "database",
        "schema.sql"
    )

    if not os.path.exists(schema_file):

        raise FileNotFoundError(
            f"Database schema file not found: {schema_file}"
        )

    with open(
        schema_file,
        "r",
        encoding="utf-8"
    ) as file:

        schema = file.read()

    conn = get_db_connection()

    try:

        conn.execute(schema)

        conn.commit()

        print("PostgreSQL database initialized successfully.")

    except Exception as e:

        conn.rollback()

        print(
            "DATABASE INITIALIZATION ERROR:",
            e
        )

        raise

    finally:

        conn.close()
