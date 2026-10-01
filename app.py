```python
import streamlit as st
import pandas as pd
from datetime import date, datetime

from database import (
    initialize_database,
    get_all_findings,
    add_finding,
    add_remediation_action,
    get_all_remediation_actions,
    update_remediation_action
)

from risk_engine import (
    calculate_inherent_risk,
    calculate_residual_risk
)

from recommendation_engine import get_recommendations


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
# HELPER FUNCTIONS
# ---------------------------------------------------------

def get_next_finding_id(findings):

    existing_numbers = []

    for finding in findings:

        finding_id = str(finding["finding_id"])

        if finding_id.startswith("F-"):

            try:
                existing_numbers.append(
                    int(finding_id.split("-")[1])
                )

            except (ValueError, IndexError):
                pass

    next_number = max(existing_numbers, default=0) + 1

    return f"F-{next_number:04d}"


def get_finding_lookup(findings):

    return {
        finding["finding_id"]: finding
        for finding in findings
    }


# ---------------------------------------------------------
# APPLICATION HEADER
# ---------------------------------------------------------

st.title("🛡️ GRC Compliance Automation Platform")

st.caption(
    "Governance • Risk • Compliance"
)

st.divider()


# ---------------------------------------------------------
# NAVIGATION
# ---------------------------------------------------------

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Risk Assessment",
        "Remediation Tracker"
    ]
)


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

if page == "Dashboard":

    st.header("GRC Dashboard")

    findings = get_all_findings()

    total_findings = len(findings)

    open_findings = sum(
        1 for finding in findings
        if (finding["status"] or "").lower()
        not in ["closed", "resolved"]
    )

    critical_risks = sum(
        1 for finding in findings
        if (finding["severity"] or "").lower() == "critical"
    )

    overdue_findings = 0

    for finding in findings:

        due_date_value = finding["due_date"]

        if due_date_value and (
            finding["status"] or ""
        ).lower() not in ["closed", "resolved"]:

            try:

                due = date.fromisoformat(
                    str(due_date_value)
                )

                if due < date.today():
                    overdue_findings += 1

            except (ValueError, TypeError):
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

        st.download_button(
            label="Download Risk Register (CSV)",
            data=pd.DataFrame(
                display_data
            ).to_csv(index=False).encode("utf-8"),
            file_name="grc_risk_register.csv",
            mime="text/csv"
        )

    else:

        st.info(
            "No findings have been recorded yet."
        )

    # REMEDIATION SUMMARY

    st.divider()

    st.subheader("Remediation Overview")

    remediation_actions = get_all_remediation_actions()

    total_actions = len(remediation_actions)

    outstanding_actions = sum(
        1 for action in remediation_actions
        if action["status"] != "Closed"
    )

    closed_actions = sum(
        1 for action in remediation_actions
        if action["status"] == "Closed"
    )

    rem_col1, rem_col2, rem_col3 = st.columns(3)

    rem_col1.metric(
        "Total Remediation Actions",
        total_actions
    )

    rem_col2.metric(
        "Outstanding Actions",
        outstanding_actions
    )

    rem_col3.metric(
        "Closed Actions",
        closed_actions
    )

    st.divider()

    st.subheader("System Status")

    st.success(
        "Database initialized successfully"
    )

    st.write(
        f"{total_findings} finding(s) currently stored"
    )


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

    st.subheader("Finding Details")

    with st.form("risk_assessment_form"):

        title = st.text_input(
            "Finding Title",
            placeholder="Example: Critical patches not applied"
        )

        description = st.text_area(
            "Describe the finding",
            placeholder=(
                "Describe the issue, affected systems, "
                "and relevant circumstances..."
            ),
            height=120
        )

        category = st.selectbox(
            "Risk Category",
            [
                "Access Control",
                "Vulnerability Management",
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
                    f"{x} - "
                    f"{['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x]}"
                )
            )

        with inherent_col2:

            inherent_impact = st.selectbox(
                "Inherent Impact",
                options=[1, 2, 3, 4, 5],
                index=2,
                format_func=lambda x: (
                    f"{x} - "
                    f"{['', 'Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'][x]}"
                )
            )

        st.divider()

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
                    f"{x} - "
                    f"{['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x]}"
                )
            )

        with residual_col2:

            residual_impact = st.selectbox(
                "Residual Impact",
                options=[1, 2, 3, 4, 5],
                index=2,
                format_func=lambda x: (
                    f"{x} - "
                    f"{['', 'Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'][x]}"
                )
            )

        submitted = st.form_submit_button(
            "Calculate Risk and Save Finding",
            use_container_width=True
        )

    if submitted:

        if not title.strip():

            st.error(
                "Please enter a finding title."
            )

        elif not description.strip():

            st.error(
                "Please describe the finding."
            )

        elif not owner.strip():

            st.error(
                "Please enter a risk owner."
            )

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

                current_findings = get_all_findings()

                finding_id = get_next_finding_id(
                    current_findings
                )

                timestamp = datetime.now().isoformat(
                    timespec="seconds"
                )

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

                st.subheader(
                    "Risk Assessment Results"
                )

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

                st.divider()

                st.header("🤖 GRC Recommendations")

                st.caption(
                    "Rule-based recommendations generated from "
                    "the finding description."
                )

                recommendations = get_recommendations(
                    title=title,
                    description=description,
                    category=category
                )

                st.info(
                    "Human review required: These are suggested "
                    "control alignments, remediation actions and "
                    "evidence items. They are not automatically "
                    "approved compliance conclusions."
                )

                st.subheader(
                    "Finding Classification"
                )

                st.write(
                    recommendations["finding_type"]
                )

                if recommendations["matched"]:

                    st.success(
                        "Relevant finding patterns were identified."
                    )

                else:

                    st.warning(
                        "No specific pattern was identified. "
                        "General recommendations are displayed."
                    )

                st.subheader(
                    "ISO 27001:2022 Control Suggestions"
                )

                if recommendations["iso_controls"]:

                    for control in recommendations["iso_controls"]:

                        with st.expander(
                            f'{control["control"]} - {control["name"]}'
                        ):

                            st.write(
                                control["reason"]
                            )

                else:

                    st.write(
                        "No specific ISO control suggestion available."
                    )

                st.subheader(
                    "NIST SP 800-53 Control Suggestions"
                )

                if recommendations["nist_controls"]:

                    for control in recommendations["nist_controls"]:

                        st.markdown(
                            f'- **{control["control"]}** — '
                            f'{control["name"]}'
                        )

                else:

                    st.write(
                        "No specific NIST control suggestion available."
                    )

                st.subheader(
                    "Recommended Remediation Actions"
                )

                for action in recommendations["remediation"]:

                    st.markdown(
                        f"- {action}"
                    )

                st.subheader(
                    "Suggested Audit Evidence"
                )

                for evidence_item in recommendations["evidence"]:

                    st.markdown(
                        f"- {evidence_item}"
                    )

                st.divider()

                st.info(
                    "The finding has been saved. Recommendations "
                    "are displayed for review; they are not stored "
                    "as approved controls or verified evidence."
                )

                st.caption(
                    "Verify suggested control references and "
                    "applicability against your framework "
                    "documentation and organizational scope."
                )

            except ValueError as error:

                st.error(
                    f"Risk assessment error: {error}"
                )

            except Exception as error:

                st.error(
                    f"An unexpected error occurred: {error}"
                )


# ---------------------------------------------------------
# REMEDIATION TRACKER
# ---------------------------------------------------------

elif page == "Remediation Tracker":

    st.header("Remediation Tracker")

    st.write(
        "Create, assign and monitor corrective actions "
        "against recorded GRC findings."
    )

    st.divider()

    findings = get_all_findings()

    if not findings:

        st.warning(
            "No findings are available. Create a risk assessment first."
        )

    else:

        finding_options = [
            finding["finding_id"]
            for finding in findings
        ]

        finding_lookup = get_finding_lookup(
            findings
        )

        # CREATE REMEDIATION ACTION

        st.subheader("Create Remediation Action")

        with st.form("create_remediation_form"):

            selected_finding_id = st.selectbox(
                "Select Finding",
                finding_options
            )

            selected_finding = finding_lookup[
                selected_finding_id
            ]

            st.caption(
                f'Finding: {selected_finding["title"]}'
            )

            action = st.text_area(
                "Corrective Action",
                placeholder=(
                    "Describe the action required to resolve the finding."
                )
            )

            action_owner = st.text_input(
                "Assigned Owner",
                value=selected_finding["owner"] or ""
            )

            action_due_date = st.date_input(
                "Remediation Deadline",
                value=date.today()
            )

            create_action = st.form_submit_button(
                "Save Remediation Action",
                use_container_width=True
            )

        if create_action:

            if not action.strip():

                st.error(
                    "Please enter a corrective action."
                )

            elif not action_owner.strip():

                st.error(
                    "Please enter an action owner."
                )

            else:

                try:

                    add_remediation_action(
                        finding_id=selected_finding_id,
                        action=action.strip(),
                        owner=action_owner.strip(),
                        due_date=action_due_date.isoformat(),
                        status="Open",
                        completion_notes=""
                    )

                    st.success(
                        "Remediation action saved successfully."
                    )

                except Exception as error:

                    st.error(
                        f"Unable to save remediation action: {error}"
                    )

        st.divider()

        # UPDATE REMEDIATION ACTION

        st.subheader("Update Remediation Progress")

        actions = get_all_remediation_actions()

        if actions:

            action_options = [
                item["id"]
                for item in actions
            ]

            selected_action_id = st.selectbox(
                "Select Remediation Action",
                action_options,
                format_func=lambda action_id: next(
                    (
                        f'Action #{item["id"]} - '
                        f'{item["action"][:65]}'
                        for item in actions
                        if item["id"] == action_id
                    ),
                    str(action_id)
                )
            )

            selected_action = next(
                item for item in actions
                if item["id"] == selected_action_id
            )

            try:

                existing_due_date = date.fromisoformat(
                    str(selected_action["due_date"])
                )

            except (ValueError, TypeError):

                existing_due_date = date.today()

            status_options = [
                "Open",
                "In Progress",
                "Under Review",
                "Closed"
            ]

            current_status = selected_action["status"]

            status_index = (
                status_options.index(current_status)
                if current_status in status_options
                else 0
            )

            with st.form("update_remediation_form"):

                st.write(
                    f'**Finding ID:** {selected_action["finding_id"]}'
                )

                st.write(
                    f'**Action:** {selected_action["action"]}'
                )

                updated_status = st.selectbox(
                    "Remediation Status",
                    status_options,
                    index=status_index
                )

                updated_owner = st.text_input(
                    "Assigned Owner",
                    value=selected_action["owner"] or ""
                )

                updated_due_date = st.date_input(
                    "Remediation Deadline",
                    value=existing_due_date
                )

                completion_notes = st.text_area(
                    "Completion Notes / Progress Update",
                    value=selected_action["completion_notes"] or "",
                    placeholder=(
                        "Describe work completed, outstanding issues "
                        "or verification results."
                    )
                )

                update_action = st.form_submit_button(
                    "Update Remediation",
                    use_container_width=True
                )

            if update_action:

                if not updated_owner.strip():

                    st.error(
                        "Please enter an assigned owner."
                    )

                else:

                    try:

                        updated = update_remediation_action(
                            action_id=selected_action_id,
                            status=updated_status,
                            owner=updated_owner.strip(),
                            due_date=updated_due_date.isoformat(),
                            completion_notes=completion_notes.strip()
                        )

                        if updated:

                            st.success(
                                "Remediation progress updated successfully."
                            )

                        else:

                            st.error(
                                "Unable to find the selected action."
                            )

                    except Exception as error:

                        st.error(
                            f"Unable to update remediation: {error}"
                        )

        else:

            st.info(
                "No remediation actions have been created yet."
            )

        st.divider()

        # REMEDIATION REGISTER

        st.subheader("Remediation Register")

        actions = get_all_remediation_actions()

        if actions:

            outstanding_actions = sum(
                1 for item in actions
                if item["status"] != "Closed"
            )

            closed_actions = sum(
                1 for item in actions
                if item["status"] == "Closed"
            )

            metric1, metric2, metric3 = st.columns(3)

            metric1.metric(
                "Total Actions",
                len(actions)
            )

            metric2.metric(
                "Outstanding",
                outstanding_actions
            )

            metric3.metric(
                "Closed",
                closed_actions
            )

            register_data = []

            for item in actions:

                register_data.append({
                    "Action ID": item["id"],
                    "Finding ID": item["finding_id"],
                    "Action": item["action"],
                    "Owner": item["owner"],
                    "Due Date": item["due_date"],
                    "Status": item["status"],
                    "Updated": item["updated_at"]
                })

            st.dataframe(
                register_data,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                label="Download Remediation Register (CSV)",
                data=pd.DataFrame(
                    register_data
                ).to_csv(index=False).encode("utf-8"),
                file_name="grc_remediation_register.csv",
                mime="text/csv"
            )

        else:

            st.info(
                "Save your first remediation action to populate this register."
            )
```
