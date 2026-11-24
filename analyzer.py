"""
analyzer.py - Turns the check results into a score, a class and advice.

Scoring (total 100):
    Length              up to 25
    Upper + lowercase   15
    Number              15
    Special character   15
    Not guessable       15
    Not common          15

Classes: 0-49 WEAK, 50-79 MEDIUM, 80-100 STRONG.
A common password is ALWAYS WEAK, even if its score is high.
"""

import checker

WEAK_LIMIT = 50      # score below this = WEAK
STRONG_LIMIT = 80    # score at or above this = STRONG
POINTS_PER_CHECK = 15

# Friendly names for each check (used on screen and in the report)
CHECK_NAMES = {
    "min_length": "Minimum length (" + str(checker.MIN_LENGTH) + "+ characters)",
    "upper_lower": "Uppercase and lowercase letters",
    "digit": "Contains a number",
    "special": "Contains a special character",
    "not_guessable": "Not easy to guess",
    "not_common": "Not in common password list",
}


def length_score(password):
    """Give more points to longer passwords (maximum 25)."""
    length = len(password)
    if length >= checker.STRONG_LENGTH:
        return 25
    elif length >= checker.MIN_LENGTH:
        return 15
    elif length >= 6:
        return 5
    return 0


def classify(score, is_not_common):
    """Return WEAK, MEDIUM or STRONG."""
    if not is_not_common:
        return "WEAK"
    if score >= STRONG_LIMIT:
        return "STRONG"
    elif score >= WEAK_LIMIT:
        return "MEDIUM"
    return "WEAK"


def build_recommendations(checks, patterns):
    """Create simple advice for every check that failed."""
    tips = []
    if not checks["min_length"]:
        tips.append("Use at least " + str(checker.MIN_LENGTH) + " characters (12 or more is better).")
    if not checks["upper_lower"]:
        tips.append("Mix UPPERCASE and lowercase letters.")
    if not checks["digit"]:
        tips.append("Add at least one number (0-9).")
    if not checks["special"]:
        tips.append("Add a special character such as ! @ # $ %.")
    for reason in patterns:
        tips.append("Avoid predictable patterns: it " + reason + ".")
    if not checks["not_common"]:
        tips.append("It is (or is based on) a common password. Choose something unique.")
    if len(tips) == 0:
        tips.append("Good job! This password meets the security policy.")
    return tips


def analyze_password(password, common_passwords):
    """Run all checks on one password and return a result dictionary.

    The result does NOT contain the password itself - only its length,
    so it is safe to use in reports.
    """
    patterns = checker.find_guessable_patterns(password)
    checks = {
        "min_length": checker.check_length(password),
        "upper_lower": checker.check_upper_lower(password),
        "digit": checker.check_digit(password),
        "special": checker.check_special(password),
        "not_guessable": len(patterns) == 0,
        "not_common": checker.check_not_common(password, common_passwords),
    }

    score = length_score(password)
    for key in ["upper_lower", "digit", "special", "not_guessable", "not_common"]:
        if checks[key]:
            score += POINTS_PER_CHECK

    # Check 7: the policy passes only if ALL checks pass
    policy_pass = all(checks.values())

    return {
        "length": len(password),
        "score": score,
        "strength": classify(score, checks["not_common"]),
        "policy_pass": policy_pass,
        "checks": checks,
        "recommendations": build_recommendations(checks, patterns),
    }
