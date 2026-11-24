"""
main.py - Entry point of PassGuard (Password Security Auditor).

Run with:  python main.py

Flow: disclaimer -> permission check -> menu -> audit -> results/report
"""

import os
import getpass

import checker
import analyzer
import report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMMON_FILE = os.path.join(BASE_DIR, "data", "common_passwords.txt")
TEST_FILE = os.path.join(BASE_DIR, "data", "test_passwords.txt")

DISCLAIMER = """
==================================================================
            PassGuard - Password Security Auditor v1.0.0
                       by Group CIPHERX
==================================================================
 ETHICAL HACKING DISCLAIMER
 - This tool is for EDUCATIONAL and AUTHORISED auditing only.
 - Only audit passwords you own or have WRITTEN PERMISSION to test.
 - Use TEST passwords for demonstrations. Never use real passwords
   that belong to other people.
 - PassGuard does NOT save any password to files, logs or reports.
 - Misuse of this tool may break the law (e.g. Computer Crimes
   Act 1997 in Malaysia). The authors are not responsible for misuse.
==================================================================
"""


def ask_permission():
    """Ask the user to confirm they are allowed to test the passwords."""
    answer = input("Do you have permission to audit these passwords? (yes/no): ")
    return answer.strip().lower() in ["yes", "y"]


def show_result(result):
    """Print the audit result of ONE password (the password is never shown)."""
    print("\n------------------- AUDIT RESULT -------------------")
    print(f"Length         : {result['length']} characters")
    print(f"Security score : {result['score']}/100")
    print(f"Strength       : {result['strength']}")
    print("Policy status  : " + ("PASS" if result["policy_pass"] else "FAIL"))
    print("\nChecks:")
    for key, passed in result["checks"].items():
        mark = "[PASS]" if passed else "[FAIL]"
        print(f"  {mark} {analyzer.CHECK_NAMES[key]}")
    print("\nRecommendations:")
    for tip in result["recommendations"]:
        print("  - " + tip)
    print("----------------------------------------------------")


def audit_single(common_passwords):
    """Menu option 1: audit one password typed by the user (hidden input)."""
    password = getpass.getpass("Enter a TEST password to audit (input is hidden): ")
    if password == "":
        print("[!] Password cannot be empty.")
        return
    result = analyzer.analyze_password(password, common_passwords)
    password = None   # remove the password from memory as soon as possible
    show_result(result)


def load_test_passwords(file_path):
    """Read test passwords from a file (one per line, '#' = comment)."""
    passwords = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.rstrip("\n")
            if line.strip() != "" and not line.startswith("#"):
                passwords.append(line)
    return passwords


def audit_batch(common_passwords):
    """Menu option 2: audit many test passwords from a file and save a report."""
    file_path = input("Test password file (press Enter for data/test_passwords.txt): ").strip()
    if file_path == "":
        file_path = TEST_FILE
    if not os.path.exists(file_path):
        print("[!] File not found:", file_path)
        return

    passwords = load_test_passwords(file_path)
    if len(passwords) == 0:
        print("[!] The file has no passwords to audit.")
        return

    print(f"\nAuditing {len(passwords)} passwords...\n")
    all_results = []
    for number, password in enumerate(passwords, start=1):
        result = analyzer.analyze_password(password, common_passwords)
        all_results.append(result)
        status = "PASS" if result["policy_pass"] else "FAIL"
        print(f"Entry #{number:<3} Score: {result['score']:>3}/100  "
              f"{result['strength']:<6}  Policy: {status}")
    passwords.clear()   # do not keep the passwords after auditing

    summary = report.build_summary(all_results)
    print("\n==================== AUDIT SUMMARY ====================")
    print(f"Total audited    : {summary['total']}")
    print(f"WEAK             : {summary['WEAK']}")
    print(f"MEDIUM           : {summary['MEDIUM']}")
    print(f"STRONG           : {summary['STRONG']}")
    print(f"Policy compliance: {summary['passed']}/{summary['total']} ({summary['compliance']}%)")
    report_path = report.save_report(all_results, summary)
    print("Report saved to  : " + report_path)
    print("(The report does not contain any passwords.)")


def show_menu():
    print("\n=========== PassGuard Menu ===========")
    print("[1] Audit a single password")
    print("[2] Batch audit (test password file)")
    print("[3] Show password policy")
    print("[4] Exit")
    return input("Choose an option (1-4): ").strip()


def show_policy():
    print("\nMinimum Password Security Policy:")
    for name in analyzer.CHECK_NAMES.values():
        print("  * " + name)
    print(f"Classes: WEAK < {analyzer.WEAK_LIMIT} <= MEDIUM < {analyzer.STRONG_LIMIT} <= STRONG")


def main():
    print(DISCLAIMER)
    if not ask_permission():
        print("Permission not confirmed. PassGuard will now exit.")
        return

    common_passwords = checker.load_common_passwords(COMMON_FILE)
    print(f"[i] Loaded {len(common_passwords)} common passwords.")

    while True:
        choice = show_menu()
        if choice == "1":
            audit_single(common_passwords)
        elif choice == "2":
            audit_batch(common_passwords)
        elif choice == "3":
            show_policy()
        elif choice == "4":
            print("Thank you for using PassGuard. Stay secure!")
            break
        else:
            print("[!] Invalid option. Please choose 1, 2, 3 or 4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user. Goodbye.")
