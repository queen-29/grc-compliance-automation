import streamlit as st
from database import initialize_database, add_finding, get_all_findings
from risk_engine import calculate_risk_score, calculate_severity
from datetime import date, datetime

# Page configuration
st.set_page_config(
    page_title="GRC Compliance Automation",
    page_icon="🛡️",
    layout="wide"
)
initialize_database()

# Application title
st.title("🛡️ GRC Compliance Automation Platform")

st.write(
    "Governance • Risk • Compliance"
)

st.divider()

# Dashboard metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="Total Findings",
        value=0
    )

with col2:
    st.metric(
        label="Open Findings",
        value=0
    )

with col3:
    st.metric(
        label="Overdue",
        value=0
    )

with col4:
    st.metric(
        label="Critical Risks",
        value=0
    )

st.divider()

# Welcome section
st.header("Welcome")

st.write(
    """
    This platform centralizes compliance and audit activities
    into one system.

    Use the platform to manage:
    
    - Risk and audit findings
    - Remediation activities
    - Compliance metrics
    - Security questionnaire responses
    - ISO 27001 and NIST control mappings
    """
)

st.header("Risk & Audit Register")

st.write(
    "Create and track compliance risks and audit findings."
)

with st.expander("➕ Add New Finding", expanded=True):

    with st.form("add_finding_form"):

        title = st.text_input(
            "Finding Title",
            placeholder="Example: Multi-Factor Authentication not enabled"
        )

        description = st.text_area(
            "Description",
            placeholder="Describe the compliance issue or audit finding."
        )

        col1, col2 = st.columns(2)

        with col1:

            category = st.selectbox(
                "Category",
                [
                    "Access Control",
                    "Asset Management",
                    "Business Continuity",
                    "Incident Management",
                    "Third-Party Risk",
                    "Data Protection",
                    "Security Awareness",
                    "Vulnerability Management",
                    "Other"
                ]
            )

            framework = st.selectbox(
                "Framework",
                [
                    "ISO 27001",
                    "NIST CSF",
                    "NIST SP 800-53",
                    "Internal Audit",
                    "Other"
                ]
            )

            control = st.text_input(
                "Control Reference",
                placeholder="Example: A.5.15"
            )

        with col2:

            likelihood = st.slider(
                "Likelihood",
                min_value=1,
                max_value=5,
                value=3
            )

            impact = st.slider(
                "Impact",
                min_value=1,
                max_value=5,
                value=3
            )

            owner = st.text_input(
                "Finding Owner",
                placeholder="Example: IT Security"
            )

            due_date = st.date_input(
                "Remediation Due Date",
                value=date.today()
            )

        status = st.selectbox(
            "Status",
            [
                "Open",
                "In Progress",
                "Closed"
            ]
        )

        submitted = st.form_submit_button(
            "Create Finding"
        )

        if submitted:

            if not title:
                st.error("Please enter a finding title.")

            elif not owner:
                st.error("Please enter a finding owner.")

            else:

                risk_score = calculate_risk_score(
                    likelihood,
                    impact
                )

                severity = calculate_severity(
                    risk_score
                )

                now = datetime.now().isoformat(
                    timespec="seconds"
                )

                existing_findings = get_all_findings()

                finding_number = len(existing_findings) + 1

                finding_id = f"F-{finding_number:04d}"

                add_finding(
                    finding_id=finding_id,
                    title=title,
                    description=description,
                    category=category,
                    framework=framework,
                    control=control,
                    likelihood=likelihood,
                    impact=impact,
                    risk_score=risk_score,
                    severity=severity,
                    owner=owner,
                    due_date=due_date.isoformat(),
                    status=status,
                    created_at=now,
                    updated_at=now
                )

                st.success(
                    f"{finding_id} created successfully. "
                    f"Risk Score: {risk_score} ({severity})"
                )

                st.rerun()


st.divider()

st.subheader("Current Findings")

findings = get_all_findings()

if findings:

    for finding in findings:

        st.write(
            f"**{finding['finding_id']} — "
            f"{finding['title']}**"
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.write(
                f"Risk Score: **{finding['risk_score']}**"
            )

        with col2:
            st.write(
                f"Severity: **{finding['severity']}**"
            )

        with col3:
            st.write(
                f"Owner: **{finding['owner']}**"
            )

        with col4:
            st.write(
                f"Status: **{finding['status']}**"
            )

        st.caption(
            f"Due Date: {finding['due_date']} | "
            f"Framework: {finding['framework']} | "
            f"Control: {finding['control']}"
        )

        st.divider()

else:

    st.info(
        "No findings have been added yet."
    )
