"""
checker.py - Password checks for PassGuard.

Each function checks ONE rule and returns True (pass) or False (fail).
This file does not print anything and does not save anything.
"""

import os
import re
import string

# ---- Password policy settings (change these to audit a different policy) ----
MIN_LENGTH = 8        # minimum length required by the policy
STRONG_LENGTH = 12    # length that earns full marks

# Patterns that make a password easy to guess
KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "azerty"]
SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]


def check_length(password):
    """Check 1: password must have at least MIN_LENGTH characters."""
    return len(password) >= MIN_LENGTH


def check_upper_lower(password):
    """Check 2: password must have BOTH uppercase and lowercase letters."""
    has_upper = False
    has_lower = False
    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
    return has_upper and has_lower


def check_digit(password):
    """Check 3: password must contain at least one number."""
    for char in password:
        if char.isdigit():
            return True
    return False


def check_special(password):
    """Check 4: password must contain at least one special character."""
    for char in password:
        if char in string.punctuation:
            return True
    return False


def has_sequence(password, size=3):
    """Look for sequences such as '123', 'abc', '321' or 'cba'."""
    lower = password.lower()
    for sequence in SEQUENCES:
        reverse = sequence[::-1]
        for i in range(len(sequence) - size + 1):
            if sequence[i:i + size] in lower or reverse[i:i + size] in lower:
                return True
    return False


def has_repeated_chars(password, size=3):
    """Look for the same character repeated, such as 'aaa' or '111'."""
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count >= size:
                return True
        else:
            count = 1
    return False


def find_guessable_patterns(password):
    """Check 5: return a list of reasons why the password is easy to guess.

    An empty list means no predictable pattern was found.
    """
    reasons = []
    lower = password.lower()
    if has_sequence(password):
        reasons.append("contains a sequence like '123' or 'abc'")
    if has_repeated_chars(password):
        reasons.append("contains repeated characters like 'aaa'")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            reasons.append("contains a keyboard pattern like 'qwerty'")
            break
    if re.search(r"(19|20)\d\d", password):
        reasons.append("contains a year like '1999' or '2024'")
    return reasons


def load_common_passwords(file_path):
    """Read the common password list into a set (fast to search)."""
    common = set()
    if not os.path.exists(file_path):
        print("[!] Warning: common password list not found:", file_path)
        return common
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            word = line.strip().lower()
            if word != "" and not word.startswith("#"):
                common.add(word)
    return common


def check_not_common(password, common_passwords):
    """Check 6: password (or its base word) must NOT be in the common list.

    Example: 'Password123!' has the base word 'password', so it fails.
    """
    lower = password.lower()
    base_word = re.sub(r"[^a-z]", "", lower)   # keep letters only
    if lower in common_passwords:
        return False
    if base_word in common_passwords:
        return False
    return True
