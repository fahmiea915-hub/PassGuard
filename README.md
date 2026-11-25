# PassGuard - Password Security Auditor

> **Version:** 1.0.0  **Category:** Auditing  **License:** MIT
> **Course:** IKB31603 Ethical Hacking (UniKL MIIT, October 2026)  **Team:** Group CIPHERX

PassGuard audits **test passwords** against a minimum password security policy.
It scores each password from 0 to 100, classifies it as WEAK, MEDIUM or STRONG, explains
which policy rules failed, and gives advice on how to fix it. Batch audits produce a
local compliance report that **never contains any password**.

> ⚠️ **Legal notice:** Only audit passwords you own or have **written permission** to test.
> Unauthorised access to computer material is an offence under the
> **Computer Crimes Act 1997 (Malaysia)**. See [Legal Disclaimer](#legal-disclaimer).

---

## Table of Contents
1. [Team](#team)
2. [Description](#description)
3. [Attack Category](#attack-category)
4. [Attack Lifecycle Mapping](#attack-lifecycle-mapping)
5. [Features](#features)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Example Output](#example-output)
9. [Project Structure](#project-structure)
10. [Ethical Considerations](#ethical-considerations)
11. [Rules of Engagement (RoE)](#rules-of-engagement-roe)
12. [Responsible Disclosure](#responsible-disclosure)
13. [Legal Disclaimer](#legal-disclaimer)
14. [Limitations](#limitations)
15. [License](#license)

---

## Team

| Name | Student ID | Role |
|------|-----------|------|
| _Member 1_ | _ID_ | _e.g. Checks module (checker.py)_ |
| _Member 2_ | _ID_ | _e.g. Scoring module (analyzer.py)_ |
| _Member 3_ | _ID_ | _e.g. Reporting module (report.py)_ |
| _Member 4_ | _ID_ | _e.g. CLI, documentation and testing_ |

---

## Description

Weak and reused passwords remain one of the most common ways attackers gain initial access.
Security teams therefore need a quick way to check whether passwords follow the organisation's
password policy **before** an attacker finds the weak ones.

PassGuard is a command-line auditor that:

- runs **six policy checks** on every password,
- computes a **security score (0-100)** and a **strength class**,
- detects **guessable patterns** (sequences, repeats, keyboard walks, years),
- compares each password and its **base word** against a list of common/breached passwords,
- produces a **password-free compliance report** for batch audits.

PassGuard is **defensive**: it never attacks a live system, never sends data over the network,
and only works on passwords that the authorised auditor provides.

---

## Attack Category

**Category 5 - Auditing** (password policy compliance auditor).

PassGuard checks whether a set of credentials complies with a minimum security policy, in the same
spirit as a CIS benchmark or compliance scanner, but focused on password strength.

---

## Attack Lifecycle Mapping

| Lifecycle phase | How PassGuard supports it | Code |
|-----------------|---------------------------|------|
| **1. Planning & Authorisation** | Legal disclaimer, mandatory permission confirmation, and an authorised **scope** that is recorded in every report. | `main.py` → `ask_permission()`, `ask_scope()` |
| **2. Reconnaissance** | Loads intelligence on how attackers guess passwords: a list of common/breached passwords and known keyboard patterns. | `checker.py` → `load_common_passwords()`, `KEYBOARD_PATTERNS` |
| **3. Scanning & Enumeration** | Runs six checks on every password: length, upper + lower case, digit, special character, guessable patterns, common list. | `checker.py` → `check_*()`, `find_guessable_patterns()` |
| **4. Vulnerability Analysis** | Converts check results into a score (0-100), a WEAK/MEDIUM/STRONG class, and a PASS/FAIL policy result. A common password is always WEAK. | `analyzer.py` → `analyze_password()`, `classify()` |
| **5. Exploitation** | **Deliberately not performed.** PassGuard does not crack hashes or try logins. It only shows which passwords an attacker *could* easily guess. | - |
| **6. Reporting & Remediation** | Prints per-password advice and saves a compliance report (counts, compliance %, failed checks) **without any passwords**. | `analyzer.py` → `build_recommendations()`, `report.py` → `save_report()` |

---

## Features

- ✅ Six policy checks with clear PASS/FAIL output
- ✅ Score 0-100 with WEAK (< 50), MEDIUM (50-79) and STRONG (≥ 80) classes
- ✅ Pattern detection: `123` / `abc` sequences (forward and reverse), `aaa` repeats, `qwerty`-style keyboard walks, years such as `1999`/`2024`
- ✅ Base-word check: `Password123!` fails because its base word `password` is common
- ✅ Hidden password input (`getpass`), so passwords are never shown on screen
- ✅ Batch audit with a summary and a password-free report
- ✅ Command-line options **and** an interactive menu
- ✅ Kill switch: `Ctrl+C` stops the tool cleanly at any time
- ✅ No external dependencies (Python standard library only)

---

## Installation

**Requirements:** Python 3.8 or newer. No third-party packages are needed.

```bash
git clone https://github.com/fahmiea915-hub/PassGuard.git
cd PassGuard
pip install -r requirements.txt   # optional: nothing to install, standard library only
python main.py --help
```

---

## Usage

```text
usage: passguard [-h] [-s | -f PATH | -p] [--scope TEXT] [-o DIR] [-v]
```

| Option | Description |
|--------|-------------|
| *(none)* | Open the interactive menu |
| `-s`, `--single` | Audit one password (hidden input) |
| `-f`, `--file PATH` | Batch audit a file of test passwords (one per line, `#` = comment) |
| `-p`, `--policy` | Show the password policy and exit |
| `--scope TEXT` | Who/what you are authorised to audit (saved in the report) |
| `-o`, `--output DIR` | Local folder for reports (default: `reports/`) |
| `-v`, `--version` | Show the version |
| `-h`, `--help` | Show help with examples |

### Examples

```bash
# Interactive menu
python main.py

# Audit one test password (input is hidden)
python main.py --single

# Batch audit the included fake test passwords (safe default)
python main.py --file data/test_passwords.txt

# Batch audit with a named scope, saving the report in results/
python main.py -f my_tests.txt --scope "CIPHERX lab accounts" -o results

# Show the policy
python main.py --policy
```

Every audit run shows the legal disclaimer and asks
`Do you have permission to audit these passwords? (yes/no)`. Anything other than `yes` exits the tool.

---

## Example Output

<!-- TODO: add screenshots, e.g. docs/screenshots/batch_audit.png -->
<!-- ![Batch audit](docs/screenshots/batch_audit.png) -->

```text
Auditing 10 passwords...

Entry #1   Score:  15/100  WEAK    Policy: FAIL
Entry #4   Score:  70/100  WEAK    Policy: FAIL
Entry #6   Score:  75/100  MEDIUM  Policy: FAIL
Entry #9   Score: 100/100  STRONG  Policy: PASS
...
==================== AUDIT SUMMARY ====================
Scope            : Local test data (data/test_passwords.txt)
Total audited    : 10
WEAK             : 5
MEDIUM           : 2
STRONG           : 3
Policy compliance: 3/10 (30.0%)
Report saved to  : reports/audit_report_20261124_173330.txt
(The report does not contain any passwords.)
```

---

## Project Structure

```text
PassGuard/
├── main.py                  # CLI (argparse + menu), disclaimer, permission, scope, kill switch
├── checker.py               # The six policy checks and pattern detection
├── analyzer.py              # Scoring, classification and recommendations
├── report.py                # Summary and password-free report generation
├── data/
│   ├── common_passwords.txt # Common/breached password list (lowercase)
│   └── test_passwords.txt   # FAKE test passwords for demonstrations
├── reports/                 # Generated reports (git-ignored, created on first run)
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Ethical Considerations

| Guardrail | What PassGuard does | Why |
|-----------|---------------------|-----|
| **Authorisation** | Disclaimer and `yes/no` permission prompt on every audit run; it cannot be skipped by any option. | The auditor must consciously confirm permission before any password is processed. |
| **Scope** | The auditor states the authorised scope; it is printed and saved in the report. | Creates accountability: every report shows what the audit was authorised for. |
| **Safe defaults** | The default input is `data/test_passwords.txt`, which contains **fake** passwords only. The default scope is "Local test data". | An accidental run cannot touch real credentials. |
| **No network activity** | PassGuard makes no network connections. | No risk of exfiltration or attacking live systems. |
| **Data handling** | Passwords are typed with hidden input, never printed, never written to disk, and cleared from memory after analysis. Reports only store entry number, length, score, class and failed checks. | A leaked report must not leak passwords. |
| **Local, labelled output** | Reports go to a local `reports/` folder (or `--output`), named `audit_report_YYYYMMDD_HHMMSS.txt`, and `reports/` is git-ignored. | Clear labelling and no accidental publishing to GitHub. |
| **Kill switch** | `Ctrl+C` (or closing input) stops the tool immediately with a clean message; menu option `[4]` exits. | The auditor can abort at any moment. |
| **No exploitation** | PassGuard does not crack hashes or attempt logins. | Keeps the tool defensive and low-risk. |

---

## Rules of Engagement (RoE)

<!-- TEAM: review and adapt this section to your real engagement before submission. -->

**1. Authorised scope**
- Only password lists provided by, or approved in writing by, the system/account owner.
- For coursework: only the fake passwords in `data/test_passwords.txt` or test passwords created by Group CIPHERX.
- The scope must be stated with `--scope` (or at the prompt) and is recorded in the report.

**2. Time windows**
- Audits are run only during the agreed window, e.g. **Monday-Friday, 09:00-17:00 (MYT)**, or during scheduled lab sessions.
- Any audit outside the window needs new written approval from the owner.

**3. Permitted techniques**
- Offline checks of supplied passwords against the policy: length, character classes, pattern detection, common-password comparison.
- Generating local, password-free reports.

**4. Prohibited actions**
- Auditing real passwords of other people without written permission.
- Using PassGuard output to log in to, crack or brute-force any account or system.
- Copying password lists off the authorised machine, or storing them in the repository.
- Sharing reports outside the authorised stakeholders.
- Modifying the tool to remove the disclaimer, permission prompt or data-handling protections.

**5. Emergency stop procedure**
1. Press **`Ctrl+C`** to stop PassGuard immediately.
2. Securely delete any input file that contains real passwords.
3. Inform the system owner and the team lead (or course lecturer) of what happened.
4. Do not resume until written approval is given again.

---

## Responsible Disclosure

<!-- TEAM: replace the placeholder contacts below. -->

**What to disclose:** weak or non-compliant passwords found during an authorised audit, as
**counts and failed rules only** (never the passwords themselves).

**Who to report to:**
- The **system/account owner** or their IT security officer, who authorised the audit.
- For coursework: the **course lecturer**.
- Never post findings publicly or share them with unauthorised people.

**When:**
- Report findings as soon as the audit finishes, within **7 days** at most.
- Critical findings (for example an admin account using a common password) should be reported **within 24 hours**.
- Give the owner a reasonable remediation period (e.g. **30 days**) before any re-audit.

**How:**
1. Share the PassGuard report through a private channel (e.g. official email or the organisation's ticket system).
2. Include the scope, date, summary counts, compliance rate and the recommendations.
3. Offer a re-audit after the passwords have been changed.

**Reporting a bug in PassGuard itself:** please open a GitHub issue *without* including real
passwords, or contact the team at _team contact email_.

---

## Legal Disclaimer

PassGuard is provided for **educational purposes and authorised security auditing only**.

- You must own the passwords or have **explicit written permission** to audit them.
- Unauthorised access to, or misuse of, computer material may be an offence under the
  **Computer Crimes Act 1997 (Malaysia)** and similar laws in other countries.
- The authors (Group CIPHERX) accept **no liability** for misuse of this tool or for any damage it causes.
- The software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)).

---

## Limitations

- The common-password list is small (about 60 entries). Real audits should use a larger list.
- Pattern detection is rule-based. It does not catch every human pattern (e.g. names, dates in other formats, leetspeak such as `p@55w0rd`).
- The score is a policy score, not a true entropy or cracking-time estimate.
- Only plain-text test passwords are supported. It does not read password hashes or directory services.
- The policy (minimum length, scoring) is set in code (`checker.py`, `analyzer.py`), not in a configuration file.
- Command-line interface only. No graphical interface.

**Future improvements:** larger breach lists (for example a k-anonymity lookup with explicit consent), leetspeak normalisation, entropy estimation, a configurable policy file, and CSV/JSON report export.

---

## License

Released under the [MIT License](LICENSE). © 2026 Group CIPHERX.
