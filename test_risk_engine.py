from risk_engine import (
    calculate_risk,
    calculate_inherent_risk,
    calculate_residual_risk
)


def test_risk_calculation():

    result = calculate_risk(4, 5)

    assert result["score"] == 20
    assert result["severity"] == "Critical"


def test_low_risk():

    result = calculate_risk(1, 2)

    assert result["score"] == 2
    assert result["severity"] == "Low"


def test_inherent_and_residual():

    inherent = calculate_inherent_risk(5, 5)
    residual = calculate_residual_risk(3, 5)

    assert inherent["score"] == 25
    assert residual["score"] == 15


def test_invalid_scores():

    try:
        calculate_risk(6, 5)
        assert False, "Invalid likelihood was accepted"

    except ValueError:
        pass


test_risk_calculation()
test_low_risk()
test_inherent_and_residual()
test_invalid_scores()

print("All risk engine tests passed.")
