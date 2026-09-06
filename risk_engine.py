"""
Risk scoring engine for the GRC Compliance Automation Platform.

This module calculates inherent and residual risk
using likelihood × impact.
"""


# ---------------------------------------------------------
# Risk scales
# ---------------------------------------------------------

LIKELIHOOD_LEVELS = {
    1: "Rare",
    2: "Unlikely",
    3: "Possible",
    4: "Likely",
    5: "Almost Certain"
}


IMPACT_LEVELS = {
    1: "Insignificant",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Severe"
}


# ---------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------

def get_severity(score):
    """
    Convert a numerical risk score into a severity rating.
    """

    if score >= 20:
        return "Critical"

    if score >= 12:
        return "High"

    if score >= 6:
        return "Medium"

    return "Low"


# ---------------------------------------------------------
# Risk calculation
# ---------------------------------------------------------

def calculate_risk(likelihood, impact):
    """
    Calculate risk using:

        Risk Score = Likelihood × Impact

    Returns the score and severity.
    """

    score = likelihood * impact
    severity = get_severity(score)

    return {
        "score": score,
        "severity": severity
    }


# ---------------------------------------------------------
# Inherent risk
# ---------------------------------------------------------

def calculate_inherent_risk(likelihood, impact):
    """
    Calculate risk before considering existing controls.
    """

    result = calculate_risk(
        likelihood,
        impact
    )

    return {
        "likelihood": likelihood,
        "likelihood_label": LIKELIHOOD_LEVELS[likelihood],
        "impact": impact,
        "impact_label": IMPACT_LEVELS[impact],
        "score": result["score"],
        "severity": result["severity"]
    }


# ---------------------------------------------------------
# Residual risk
# ---------------------------------------------------------

def calculate_residual_risk(likelihood, impact):
    """
    Calculate risk after considering existing controls.
    """

    result = calculate_risk(
        likelihood,
        impact
    )

    return {
        "likelihood": likelihood,
        "likelihood_label": LIKELIHOOD_LEVELS[likelihood],
        "impact": impact,
        "impact_label": IMPACT_LEVELS[impact],
        "score": result["score"],
        "severity": result["severity"]
    }


# ---------------------------------------------------------
# Risk assessment summary
# ---------------------------------------------------------

def build_risk_assessment(
    inherent_likelihood,
    inherent_impact,
    residual_likelihood,
    residual_impact
):
    """
    Build a complete risk assessment containing
    both inherent and residual risk.
    """

    inherent = calculate_inherent_risk(
        inherent_likelihood,
        inherent_impact
    )

    residual = calculate_residual_risk(
        residual_likelihood,
        residual_impact
    )

    return {
        "inherent": inherent,
        "residual": residual
    }
