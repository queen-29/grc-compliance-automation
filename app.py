import streamlit as st
from database import initialize_database, get_all_findings


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="GRC Compliance Automation",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# Initialize database
# ---------------------------------------------------------

initialize_database()


# ---------------------------------------------------------
# Load findings
# ---------------------------------------------------------

findings = get_all_findings()


# ---------------------------------------------------------
# Application title
# ---------------------------------------------------------

st.title("🛡️ GRC Compliance Automation Platform")

st.write("Governance • Risk • Compliance")

st.divider()


# ---------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------

total_findings = len(findings)

open_findings = sum(
    1 for finding in findings
    if finding["status"].lower() not in ["closed", "resolved"]
)

critical_risks = sum(
    1 for finding in findings
    if finding["severity"].lower() == "critical"
)


overdue_findings = 0

for finding in findings:

    due_date = finding["due_date"]

    if due_date and finding["status"].lower() not in ["closed", "resolved"]:
        try:
            from datetime import date

            due = date.fromisoformat(due_date)

            if due < date.today():
                overdue_findings += 1

        except ValueError:
            pass


col1, col2, col3, col4 = st.columns(4)


with col1:
    st.metric(
        label="Total Findings",
        value=total_findings
    )


with col2:
    st.metric(
        label="Open Findings",
        value=open_findings
    )


with col3:
    st.metric(
        label="Overdue",
        value=overdue_findings
    )


with col4:
    st.metric(
        label="Critical Risks",
        value=critical_risks
    )


st.divider()


# ---------------------------------------------------------
# Risk & Audit Register
# ---------------------------------------------------------

st.header("Risk & Audit Register")


if findings:

    display_data = []

    for finding in findings:

        display_data.append({
            "Finding ID": finding["finding_id"],
            "Title": finding["title"],
            "Category": finding["category"],
            "Framework": finding["framework"] or "",
            "Control": finding["control"] or "",
            "Risk Score": finding["risk_score"],
            "Severity": finding["severity"],
            "Owner": finding["owner"] or "",
            "Due Date": finding["due_date"] or "",
            "Status": finding["status"]
        })

    st.dataframe(
        display_data,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No findings have been recorded yet. "
        "The Risk Register will appear here once findings are added."
    )


st.divider()


# ---------------------------------------------------------
# System status
# ---------------------------------------------------------

st.header("System Status")

status_col1, status_col2 = st.columns(2)


with status_col1:
    st.success("Database initialized successfully")


with status_col2:
    st.info(
        f"{total_findings} finding(s) currently stored"
    )


st.divider()


# ---------------------------------------------------------
# Welcome section
# ---------------------------------------------------------

st.header("About the Platform")

st.write(
    """
    This platform centralizes governance, risk, and compliance
    activities into one system.

    Current capabilities include:

    - Risk and audit finding storage
    - Risk severity tracking
    - Due-date monitoring
    - Finding status tracking
    - Compliance framework and control references
    - Dashboard metrics

    Additional compliance automation capabilities will be
    added incrementally.
    """
)
