import sqlite3
from pathlib import Path


# Location of our SQLite database
DATABASE_DIR = Path("data")
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "grc.db"


def get_connection():
    """Create and return a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the findings table if it does not already exist."""

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            finding_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,

            category TEXT NOT NULL,
            framework TEXT,
            control TEXT,

            likelihood INTEGER NOT NULL,
            impact INTEGER NOT NULL,

            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,

            owner TEXT,
            due_date TEXT,

            status TEXT NOT NULL,

            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def add_finding(
    finding_id,
    title,
    description,
    category,
    framework,
    control,
    likelihood,
    impact,
    risk_score,
    severity,
    owner,
    due_date,
    status,
    created_at,
    updated_at
):
    """Add a new finding to the database."""

    connection = get_connection()

    connection.execute("""
        INSERT INTO findings (
            finding_id,
            title,
            description,
            category,
            framework,
            control,
            likelihood,
            impact,
            risk_score,
            severity,
            owner,
            due_date,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        title,
        description,
        category,
        framework,
        control,
        likelihood,
        impact,
        risk_score,
        severity,
        owner,
        due_date,
        status,
        created_at,
        updated_at
    ))

    connection.commit()
    connection.close()


def get_all_findings():
    """Return all findings from the database."""

    connection = get_connection()

    findings = connection.execute("""
        SELECT *
        FROM findings
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return findings
