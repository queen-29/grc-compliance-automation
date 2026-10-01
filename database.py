
import sqlite3
from pathlib import Path


# ---------------------------------------------------------
# DATABASE CONFIGURATION
# ---------------------------------------------------------

DATABASE_DIR = Path("data")
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "grc.db"


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# ---------------------------------------------------------
# DATABASE INITIALIZATION AND MIGRATION
# ---------------------------------------------------------

def initialize_database():

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

    # Add new risk assessment fields to existing databases.
    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(findings)"
        ).fetchall()
    }

    new_columns = {
        "inherent_likelihood": "INTEGER",
        "inherent_impact": "INTEGER",
        "inherent_risk_score": "INTEGER",
        "inherent_severity": "TEXT",
        "residual_likelihood": "INTEGER",
        "residual_impact": "INTEGER",
        "residual_risk_score": "INTEGER",
        "residual_severity": "TEXT"
    }

    for column, data_type in new_columns.items():

        if column not in existing_columns:

            connection.execute(
                f"ALTER TABLE findings ADD COLUMN {column} {data_type}"
            )

    # Preserve existing records by copying their old scores
    # into the new residual-risk fields.
    connection.execute("""
        UPDATE findings
        SET
            residual_likelihood = likelihood,
            residual_impact = impact,
            residual_risk_score = risk_score,
            residual_severity = severity
        WHERE residual_risk_score IS NULL
    """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# ADD FINDING
# ---------------------------------------------------------

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
    updated_at,
    inherent_likelihood=None,
    inherent_impact=None,
    inherent_risk_score=None,
    inherent_severity=None,
    residual_likelihood=None,
    residual_impact=None,
    residual_risk_score=None,
    residual_severity=None
):

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
            updated_at,
            inherent_likelihood,
            inherent_impact,
            inherent_risk_score,
            inherent_severity,
            residual_likelihood,
            residual_impact,
            residual_risk_score,
            residual_severity
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?
        )
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
        updated_at,
        inherent_likelihood,
        inherent_impact,
        inherent_risk_score,
        inherent_severity,
        residual_likelihood,
        residual_impact,
        residual_risk_score,
        residual_severity
    ))

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# RETRIEVE FINDINGS
# ---------------------------------------------------------

def get_all_findings():

    connection = get_connection()

    findings = connection.execute("""
        SELECT *
        FROM findings
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return findings
