import streamlit as st

# Page configuration
st.set_page_config(
    page_title="GRC Compliance Automation",
    page_icon="🛡️",
    layout="wide"
)

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

st.info(
    "🚧 Application is currently under development. "
    "The Risk Register and database will be added next."
)
