def calculate_risk_score(likelihood, impact):
    """Calculate risk score from likelihood and impact."""
    return likelihood * impact


def calculate_severity(risk_score):
    """Classify risk based on the risk score."""

    if risk_score >= 17:
        return "Critical"
    elif risk_score >= 10:
        return "High"
    elif risk_score >= 5:
        return "Medium"
    else:
        return "Low"
