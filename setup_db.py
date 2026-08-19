import sqlite3

DATABASE = "database/database.db"

conn = sqlite3.connect(DATABASE)

conn.executescript("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    status_code INTEGER,
    https_enabled INTEGER DEFAULT 0,
    ssl_valid INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    incident_id INTEGER NOT NULL,
    report_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
""")

conn.commit()

print("Incidents and Reports tables created successfully!")

print(
    conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
)

conn.close()