"""
main.py - Entry point of PassGuard (Password Security Auditor).

Run with:  python main.py            (interactive menu)
           python main.py --help     (all command-line options)

Flow: arguments -> disclaimer -> permission check -> scope -> audit -> results/report
"""

import argparse
import os
import getpass

import checker
import analyzer
import report

VERSION = "1.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMMON_FILE = os.path.join(BASE_DIR, "data", "common_passwords.txt")
TEST_FILE = os.path.join(BASE_DIR, "data", "test_passwords.txt")
DEFAULT_SCOPE = "Local test data (data/test_passwords.txt)"

DISCLAIMER = """
==================================================================
            PassGuard - Password Security Auditor v""" + VERSION + """
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
 - Press Ctrl+C at any time to stop PassGuard immediately.
==================================================================
"""

EXAMPLES = """
examples:
  python main.py                       open the interactive menu
  python main.py --single              audit one password (hidden input)
  python main.py --file data/test_passwords.txt
                                       batch audit the default test file
  python main.py -f my_tests.txt --scope "CIPHERX lab accounts" -o results
                                       batch audit with a named scope and
                                       save the report in the results/ folder
  python main.py --policy              show the password policy and exit

safety:
  - The disclaimer and permission question are ALWAYS shown.
  - Passwords are never printed or saved. Reports are stored locally only.
  - Press Ctrl+C at any time to abort (kill switch).
"""


def parse_args():
    """Read the command-line options."""
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="PassGuard - audit TEST passwords against a minimum security policy.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-s", "--single", action="store_true",
                      help="audit one password typed with hidden input")
    mode.add_argument("-f", "--file", metavar="PATH",
                      help="batch audit a file of test passwords (one per line)")
    mode.add_argument("-p", "--policy", action="store_true",
                      help="show the password policy and exit")
    parser.add_argument("--scope", metavar="TEXT",
                        help="who/what you are authorised to audit (saved in the report)")
    parser.add_argument("-o", "--output", metavar="DIR", default=report.REPORT_FOLDER,
                        help="local folder for audit reports (default: reports/)")
    parser.add_argument("-v", "--version", action="version",
                        version="PassGuard " + VERSION)
    return parser.parse_args()


def ask_permission():
    """Ask the user to confirm they are allowed to test the passwords."""
    answer = input("Do you have permission to audit these passwords? (yes/no): ")
    return answer.strip().lower() in ["yes", "y"]


def ask_scope(scope_argument):
    """Get the authorised audit scope from --scope, or ask for it."""
    if scope_argument:
        scope = scope_argument.strip()
    else:
        print("\nAuthorised scope = the people/system you have permission to audit.")
        scope = input(f"Audit scope (press Enter for '{DEFAULT_SCOPE}'): ").strip()
    if scope == "":
        scope = DEFAULT_SCOPE
    print("[i] Audit scope: " + scope)
    return scope


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
    """Audit one password typed by the user (hidden input)."""
    password = getpass.getpass("Enter a TEST password to audit (input is hidden): ")
    if password == "":
        print("[!] Password cannot be empty.")
        return
    result = analyzer.analyze_password(password, common_passwords)
    password = None   # remove the password from memory as soon as possible
    show_result(result)


def load_test_passwords(file_path):
    """Read test passwords from a file (one per line, '#' = comment).

    Returns a list, or None if the file cannot be read (the tool must not crash).
    """
    if not os.path.isfile(file_path):
        print("[!] File not found (or it is a folder):", file_path)
        return None
    passwords = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.rstrip("\r\n")
                if line.strip() != "" and not line.startswith("#"):
                    passwords.append(line)
    except UnicodeDecodeError:
        print("[!] The file is not a UTF-8 text file:", file_path)
        return None
    except OSError as error:
        print("[!] Cannot read the file:", error)
        return None
    return passwords


def audit_batch(common_passwords, scope, output_folder, file_path=None):
    """Audit many test passwords from a file and save a report."""
    if file_path is None:
        file_path = input("Test password file (press Enter for data/test_passwords.txt): ").strip()
        if file_path == "":
            file_path = TEST_FILE

    passwords = load_test_passwords(file_path)
    if passwords is None:
        return
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
    print(f"Scope            : {scope}")
    print(f"Total audited    : {summary['total']}")
    print(f"WEAK             : {summary['WEAK']}")
    print(f"MEDIUM           : {summary['MEDIUM']}")
    print(f"STRONG           : {summary['STRONG']}")
    print(f"Policy compliance: {summary['passed']}/{summary['total']} ({summary['compliance']}%)")
    try:
        report_path = report.save_report(all_results, summary, scope, output_folder)
    except OSError as error:
        print("[!] Could not save the report:", error)
        return
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


def run_menu(common_passwords, scope, output_folder):
    """Interactive menu (used when no mode option is given)."""
    while True:
        choice = show_menu()
        if choice == "1":
            audit_single(common_passwords)
        elif choice == "2":
            audit_batch(common_passwords, scope, output_folder)
        elif choice == "3":
            show_policy()
        elif choice == "4":
            print("Thank you for using PassGuard. Stay secure!")
            break
        else:
            print("[!] Invalid option. Please choose 1, 2, 3 or 4.")


def main():
    args = parse_args()

    # Showing the policy audits nothing, so it does not need permission.
    if args.policy:
        show_policy()
        return

    print(DISCLAIMER)
    if not ask_permission():
        print("Permission not confirmed. PassGuard will now exit.")
        return
    scope = ask_scope(args.scope)

    common_passwords = checker.load_common_passwords(COMMON_FILE)
    print(f"[i] Loaded {len(common_passwords)} common passwords.")

    if args.single:
        audit_single(common_passwords)
    elif args.file:
        audit_batch(common_passwords, scope, args.output, args.file)
    else:
        run_menu(common_passwords, scope, args.output)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        # Kill switch: Ctrl+C (or closed input) stops the tool cleanly.
        print("\n[!] Stopped by user. No passwords were saved. Goodbye.")
