"""
report.py - Builds the audit summary and saves the audit report.

ETHICS: the report NEVER contains passwords. It only stores the entry
number, length, score, class, policy result and which checks failed.
"""

import os
from datetime import datetime

import analyzer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")


def build_summary(all_results):
    """Count WEAK/MEDIUM/STRONG and calculate the policy compliance rate."""
    total = len(all_results)
    summary = {"total": total, "WEAK": 0, "MEDIUM": 0, "STRONG": 0, "passed": 0}
    for result in all_results:
        summary[result["strength"]] += 1
        if result["policy_pass"]:
            summary["passed"] += 1
    if total > 0:
        summary["compliance"] = round(summary["passed"] / total * 100, 1)
    else:
        summary["compliance"] = 0.0
    return summary


def save_report(all_results, summary):
    """Write the audit report to reports/ and return the file path."""
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    now = datetime.now()
    file_name = "audit_report_" + now.strftime("%Y%m%d_%H%M%S") + ".txt"
    file_path = os.path.join(REPORT_FOLDER, file_name)

    lines = []
    lines.append("PassGuard - Password Policy Audit Report")
    lines.append("Generated : " + now.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Note      : Passwords are NOT stored in this report.")
    lines.append("=" * 70)

    for number, result in enumerate(all_results, start=1):
        status = "PASS" if result["policy_pass"] else "FAIL"
        lines.append(
            f"Entry #{number:<3} | Length: {result['length']:<3} | "
            f"Score: {result['score']:>3}/100 | {result['strength']:<6} | Policy: {status}"
        )
        for key, passed in result["checks"].items():
            if not passed:
                lines.append("            - Failed: " + analyzer.CHECK_NAMES[key])

    lines.append("=" * 70)
    lines.append(f"Total audited   : {summary['total']}")
    lines.append(f"WEAK / MEDIUM / STRONG : {summary['WEAK']} / {summary['MEDIUM']} / {summary['STRONG']}")
    lines.append(f"Policy compliant: {summary['passed']} of {summary['total']} ({summary['compliance']}%)")

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    return file_path
