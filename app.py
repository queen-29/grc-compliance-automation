
import streamlit as st
from datetime import date, datetime

from database import (
    initialize_database,
    get_all_findings,
    add_finding
)

from risk_engine import (
    calculate_inherent_risk,
    calculate_residual_risk
)


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="GRC Compliance Automation",
    page_icon="🛡️",
    layout="wide"
)

initialize_database()


# ---------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------

findings = get_all_findings()


# ---------------------------------------------------------
# APPLICATION HEADER
# ---------------------------------------------------------

st.title("🛡️ GRC Compliance Automation Platform")

st.caption("Governance • Risk • Compliance")

st.divider()


# ---------------------------------------------------------
# NAVIGATION
# ---------------------------------------------------------

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Risk Assessment"
    ]
)


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

if page == "Dashboard":

    st.header("GRC Dashboard")

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

        if due_date and finding["status"].lower() not in [
            "closed", "resolved"
        ]:

            try:
                due = date.fromisoformat(due_date)

                if due < date.today():
                    overdue_findings += 1

            except ValueError:
                pass

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Findings", total_findings)
    col2.metric("Open Findings", open_findings)
    col3.metric("Overdue", overdue_findings)
    col4.metric("Critical Risks", critical_risks)

    st.divider()

    st.subheader("Risk & Audit Register")

    if findings:

        display_data = []

        for finding in findings:

            display_data.append({
                "Finding ID": finding["finding_id"],
                "Title": finding["title"],
                "Category": finding["category"],
                "Inherent Risk": (
                    finding["inherent_severity"]
                    or "Not assessed"
                ),
                "Residual Risk": (
                    finding["residual_severity"]
                    or finding["severity"]
                ),
                "Risk Score": (
                    finding["residual_risk_score"]
                    if finding["residual_risk_score"] is not None
                    else finding["risk_score"]
                ),
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

        st.info("No findings have been recorded yet.")

    st.divider()

    st.subheader("System Status")

    st.success("Database initialized successfully")

    st.write(f"{total_findings} finding(s) currently stored")


# ---------------------------------------------------------
# RISK ASSESSMENT
# ---------------------------------------------------------

elif page == "Risk Assessment":

    st.header("New Risk Assessment")

    st.write(
        "Describe the issue and assess its inherent "
        "and residual risk."
    )

    st.divider()

    # -----------------------------------------------------
    # FINDING DETAILS
    # -----------------------------------------------------

    st.subheader("Finding Details")

    with st.form("risk_assessment_form"):

        title = st.text_input(
            "Finding Title",
            placeholder="Example: MFA not enabled for privileged accounts"
        )

        description = st.text_area(
            "Describe the finding",
            placeholder="Describe the issue, affected systems, "
                        "and relevant circumstances...",
            height=120
        )

        category = st.selectbox(
            "Risk Category",
            [
                "Access Control",
                "Data Protection",
                "Network Security",
                "Third-Party Risk",
                "Incident Management",
                "Business Continuity",
                "Asset Management",
                "Other"
            ]
        )

        owner = st.text_input(
            "Risk Owner",
            placeholder="Example: IT Security Team"
        )

        due_date = st.date_input(
            "Target Remediation Date",
            value=date.today()
        )

        st.divider()

        # -------------------------------------------------
        # INHERENT RISK
        # -------------------------------------------------

        st.subheader("Inherent Risk")

        st.caption(
            "Assess the risk before considering existing controls."
        )

        inherent_col1, inherent_col2 = st.columns(2)

        with inherent_col1:

            inherent_likelihood = st.selectbox(
                "Inherent Likelihood",
                options=[1, 2, 3, 4, 5],
                index=2,
                format_func=lambda x: (
                    f"{x} - {['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x]}"
                )
            )

        with inherent_col2:

            inherent_impact = st.selectbox(
                "Inherent Impact",
                options=[1, 2, 3, 4, 5],
                index=2,
                format_func=lambda x: (
                    f"{x} - {['', 'Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'][x]}"
                )
            )

        st.divider()

        # -------------------------------------------------
        # RESIDUAL RISK
        # -------------------------------------------------

        st.subheader("Residual Risk")

        st.caption(
            "Assess the risk after considering existing controls."
        )

        residual_col1, residual_col2 = st.columns(2)

        with residual_col1:

            residual_likelihood = st.selectbox(
                "Residual Likelihood",
                options=[1, 2, 3, 4, 5],
                index=1,
                format_func=lambda x: (
                    f"{x} - {['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x]}"
                )
            )

        with residual_col2:

            residual_impact = st.selectbox(
                "Residual Impact",
                options=[1, 2, 3, 4, 5],
                index=2,
                format_func=lambda x: (
                    f"{x} - {['', 'Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'][x]}"
                )
            )

        submitted = st.form_submit_button(
            "Calculate Risk and Save Finding",
            use_container_width=True
        )

    # -----------------------------------------------------
    # PROCESS ASSESSMENT
    # -----------------------------------------------------

    if submitted:

        if not title.strip():
            st.error("Please enter a finding title.")

        elif not description.strip():
            st.error("Please describe the finding.")

        elif not owner.strip():
            st.error("Please enter a risk owner.")

        else:

            try:

                inherent = calculate_inherent_risk(
                    inherent_likelihood,
                    inherent_impact
                )

                residual = calculate_residual_risk(
                    residual_likelihood,
                    residual_impact
                )

                next_number = len(findings) + 1

                finding_id = f"F-{next_number:04d}"

                timestamp = datetime.now().isoformat(timespec="seconds")

                add_finding(
                    finding_id=finding_id,
                    title=title.strip(),
                    description=description.strip(),
                    category=category,
                    framework=None,
                    control=None,
                    likelihood=residual_likelihood,
                    impact=residual_impact,
                    risk_score=residual["score"],
                    severity=residual["severity"],
                    owner=owner.strip(),
                    due_date=due_date.isoformat(),
                    status="Open",
                    created_at=timestamp,
                    updated_at=timestamp,
                    inherent_likelihood=inherent_likelihood,
                    inherent_impact=inherent_impact,
                    inherent_risk_score=inherent["score"],
                    inherent_severity=inherent["severity"],
                    residual_likelihood=residual_likelihood,
                    residual_impact=residual_impact,
                    residual_risk_score=residual["score"],
                    residual_severity=residual["severity"]
                )

                st.success(
                    f"Finding {finding_id} saved successfully."
                )

                st.subheader("Risk Assessment Results")

                result_col1, result_col2 = st.columns(2)

                with result_col1:

                    st.markdown("### Inherent Risk")

                    st.metric(
                        "Risk Score",
                        f'{inherent["score"]}/25'
                    )

                    st.write(
                        f'Severity: {inherent["severity"]}'
                    )

                with result_col2:

                    st.markdown("### Residual Risk")

                    st.metric(
                        "Risk Score",
                        f'{residual["score"]}/25'
                    )

                    st.write(
                        f'Severity: {residual["severity"]}'
                    )

                st.info(
                    "The finding has been stored. "
                    "Return to the Dashboard to view it."
                )

            except ValueError as error:

                st.error(f"Risk assessment error: {error}")
