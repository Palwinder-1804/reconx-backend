def calculate_risk(summary):

    # ==========================
    # Get Severity Counts
    # ==========================

    high = summary.get(
        "high",
        0
    )

    medium = summary.get(
        "medium",
        0
    )

    low = summary.get(
        "low",
        0
    )

    # ==========================
    # Base Security Score
    # ==========================

    score = 100

    # ==========================
    # Deduct Score
    # ==========================

    score -= high * 15

    score -= medium * 7

    score -= low * 3

    # ==========================
    # Prevent Negative Score
    # ==========================

    if score < 0:

        score = 0

    # ==========================
    # Determine Risk Level
    # ==========================

    if score >= 80:

        risk = "LOW"

    elif score >= 60:

        risk = "MEDIUM"

    elif score >= 40:

        risk = "HIGH"

    else:

        risk = "CRITICAL"

    # ==========================
    # Return Result
    # ==========================

    return {

        "security_score": score,

        "risk_level": risk
    }