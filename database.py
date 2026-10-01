
import sqlite3
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------
# DATABASE CONFIGURATION
# ---------------------------------------------------------

DATABASE_DIR = Path("data")
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "grc.db"

REMEDIATION_STATUSES = [
    "Open",
    "In Progress",
    "Under Review",
    "Closed"
]


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

    try:

        # Existing findings table

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

        # Risk assessment migrations

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

        # Preserve existing risk scores

        connection.execute("""
            UPDATE findings
            SET
                residual_likelihood = likelihood,
                residual_impact = impact,
                residual_risk_score = risk_score,
                residual_severity = severity
            WHERE residual_risk_score IS NULL
        """)

        # New remediation actions table

        connection.execute("""
            CREATE TABLE IF NOT EXISTS remediation_actions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                finding_id TEXT NOT NULL,
                action TEXT NOT NULL,
                owner TEXT,
                due_date TEXT,

                status TEXT NOT NULL DEFAULT 'Open',

                completion_notes TEXT,

                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.commit()

    finally:

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

    try:

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

    finally:

        connection.close()


# ---------------------------------------------------------
# RETRIEVE FINDINGS
# ---------------------------------------------------------

def get_all_findings():

    connection = get_connection()

    try:

        findings = connection.execute("""
            SELECT *
            FROM findings
            ORDER BY id DESC
        """).fetchall()

        return findings

    finally:

        connection.close()


# ---------------------------------------------------------
# ADD REMEDIATION ACTION
# ---------------------------------------------------------

def add_remediation_action(
    finding_id,
    action,
    owner,
    due_date,
    status="Open",
    completion_notes=""
):

    if status not in REMEDIATION_STATUSES:
        raise ValueError("Invalid remediation status.")

    connection = get_connection()

    try:

        timestamp = datetime.now().isoformat(
            timespec="seconds"
        )

        cursor = connection.execute("""
            INSERT INTO remediation_actions (
                finding_id,
                action,
                owner,
                due_date,
                status,
                completion_notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id,
            action,
            owner,
            due_date,
            status,
            completion_notes,
            timestamp,
            timestamp
        ))

        connection.commit()

        return cursor.lastrowid

    finally:

        connection.close()


# ---------------------------------------------------------
# RETRIEVE REMEDIATION ACTIONS
# ---------------------------------------------------------

def get_all_remediation_actions(finding_id=None):

    connection = get_connection()

    try:

        if finding_id:

            actions = connection.execute("""
                SELECT *
                FROM remediation_actions
                WHERE finding_id = ?
                ORDER BY id DESC
            """, (finding_id,)).fetchall()

        else:

            actions = connection.execute("""
                SELECT *
                FROM remediation_actions
                ORDER BY id DESC
            """).fetchall()

        return actions

    finally:

        connection.close()


# ---------------------------------------------------------
# UPDATE REMEDIATION ACTION
# ---------------------------------------------------------

def update_remediation_action(
    action_id,
    status,
    owner=None,
    due_date=None,
    completion_notes=None
):

    if status not in REMEDIATION_STATUSES:
        raise ValueError("Invalid remediation status.")

    connection = get_connection()

    try:

        timestamp = datetime.now().isoformat(
            timespec="seconds"
        )

        cursor = connection.execute("""
            UPDATE remediation_actions

            SET
                status = ?,
                owner = ?,
                due_date = ?,
                completion_notes = ?,
                updated_at = ?

            WHERE id = ?
        """, (
            status,
            owner,
            due_date,
            completion_notes,
            timestamp,
            action_id
        ))

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()
