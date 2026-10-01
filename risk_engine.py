
"""
GRC Compliance Automation Platform
Risk Assessment Engine

Calculates inherent and residual risk using:
Risk Score = Likelihood x Impact

Initial project scoring thresholds:
1-4   Low
5-9   Medium
10-16 High
17-25 Critical
"""


# ---------------------------------------------------------
# RISK CONFIGURATION
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

RISK_THRESHOLDS = {
    "Low": (1, 4),
    "Medium": (5, 9),
    "High": (10, 16),
    "Critical": (17, 25)
}


# ---------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------

def validate_score(value, field_name):
    """Ensure likelihood and impact are integers from 1 to 5."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer.")

    if value < 1 or value > 5:
        raise ValueError(f"{field_name} must be between 1 and 5.")

    return value


# ---------------------------------------------------------
# SEVERITY CLASSIFICATION
# ---------------------------------------------------------

def get_severity(score):
    """Convert a risk score into a severity rating."""

    if isinstance(score, bool) or not isinstance(score, int):
        raise ValueError("Risk score must be an integer.")

    if score < 1 or score > 25:
        raise ValueError("Risk score must be between 1 and 25.")

    for severity, (minimum, maximum) in RISK_THRESHOLDS.items():
        if minimum <= score <= maximum:
            return severity

    raise ValueError("Unable to classify risk score.")


# ---------------------------------------------------------
# BASIC RISK CALCULATION
# ---------------------------------------------------------

def calculate_risk(likelihood, impact):
    """Calculate risk using likelihood multiplied by impact."""

    validate_score(likelihood, "Likelihood")
    validate_score(impact, "Impact")

    score = likelihood * impact

    return {
        "likelihood": likelihood,
        "likelihood_label": LIKELIHOOD_LEVELS[likelihood],
        "impact": impact,
        "impact_label": IMPACT_LEVELS[impact],
        "score": score,
        "severity": get_severity(score)
    }


# ---------------------------------------------------------
# INHERENT RISK
# ---------------------------------------------------------

def calculate_inherent_risk(likelihood, impact):
    """
    Calculate risk before considering existing controls.
    """

    result = calculate_risk(likelihood, impact)

    return {
        **result,
        "risk_type": "Inherent"
    }


# ---------------------------------------------------------
# RESIDUAL RISK
# ---------------------------------------------------------

def calculate_residual_risk(likelihood, impact):
    """
    Calculate risk after considering existing controls.
    """

    result = calculate_risk(likelihood, impact)

    return {
        **result,
        "risk_type": "Residual"
    }


# ---------------------------------------------------------
# COMPLETE RISK ASSESSMENT
# ---------------------------------------------------------

def build_risk_assessment(
    inherent_likelihood,
    inherent_impact,
    residual_likelihood,
    residual_impact
):
    """
    Calculate both inherent and residual risk.

    Residual risk is assessed separately after considering
    the effectiveness of existing controls.
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
        "residual": residual,
        "risk_reduction": (
            inherent["score"] - residual["score"]
        )
    }
