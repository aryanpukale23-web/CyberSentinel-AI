-- CYBERSENTINEL AI DATABASE SCHEMA
-- Intelligent Cyber Incident Response System

-- USERS TABLE

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- INCIDENTS TABLE

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    incident_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'Low',
    impact TEXT,
    reason TEXT,
    response_recommendation TEXT,
    prevention_tips TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    evidence_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES users(id)
);

-- REPORTS TABLE

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    incident_id INTEGER NOT NULL,
    report_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES users(id),
    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
);
