<div align="center">

<img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue?style=for-the-badge" alt="Platform" />
<img src="https://img.shields.io/badge/python-3.8%2B-yellow?style=for-the-badge&logo=python&logoColor=white" alt="Python" />

# 🔒 Aruba OS — Secure Configuration Audit Script

### *Automated security checklist review for AOS-CX devices*

**A desktop tool that parses Aruba AOS-CX configuration logs, runs structured security checks, and produces professional-grade Excel audit reports — instantly.**

[What It Does](#-what-it-does) · [Security Checks](#-security-checks) · [How to Use](#-how-to-use) · [Output Format](#-output-format) · [Requirements](#-requirements)

---

> ⚠️ **Internal Tool** — For internal security review use only. Not intended for public distribution or external deployment.

---

</div>

## 🚀 What It Does

The **Aruba OS Secure Configuration Auditor** is a Python desktop application that eliminates the manual effort of reviewing Aruba switch configurations. It reads raw configuration log files, runs a structured set of security checks, and produces a clean, colour-coded Excel report — one sheet per device — ready for stakeholder review or compliance documentation.

Built for security reviewers who audit multiple AOS-CX devices at once, it handles batch processing seamlessly: load as many configuration files as needed, run the audit in one click, and get a single consolidated `.xlsx` report.

---

## 🧩 Security Checks

The tool runs **5 automated security checks** derived from Aruba AOS-CX hardening best practices. Each check uses intent-pattern scanning to identify relevant configuration lines, and pass/fail patterns to determine compliance.

| # | Check | Severity | What It Validates |
|---|-------|----------|-------------------|
| 1 | **Password Complexity** | 🔴 High | All 7 sub-commands present: `minimum-length`, `lowercase-count`, `uppercase-count`, `special-char-count`, `numeric-count`, `history-count`, `enable` |
| 2 | **Failed Login Attempts** | 🟡 Medium | Both `console-login-attempts` and `limit-login-attempts` configured with lockout times |
| 3 | **NTP Authentication** | 🟡 Medium | `ntp authentication` enabled and `ntp authentication-key` configured |
| 4 | **SSH Allow List** | 🟡 Medium | `ssh server allow-list` block present with at least one IP and `enable` |
| 5 | **Syslog (Remote Logging)** | 🟢 Low | TLS syslog to remote server with `auth-mode subject-name vrf mgmt include-auditable-events` |

### How Checks Work

Each check uses a two-stage approach:

```
Stage 1 — Intent Scan
  Collect every config line related to the command area.
  These become the "Received Output" evidence in the report.

Stage 2 — Pass/Fail Decision
  Validate that the structurally complete, correctly configured
  version of the command is present. If not → finding raised.
```

This means the tool always shows you *what was found* even when a check fails — not just a red mark — giving auditors real evidence to work with.

---

## 🖥️ How to Use

### 1. Launch the Application

```bash
python aruba_audit_tool.py
```

The GUI launches automatically.

### 2. Add Configuration Files

Click **＋ Add Files** and select one or more Aruba AOS-CX configuration log files (`.log`, `.txt`, `.conf`). Files are listed in the panel — use **✕ Remove Selected** or **⊘ Clear All** to manage the list.

> **Tip:** The tool automatically extracts the device IP from the filename (e.g. `192.168.1.1_config.log`). If no IP is found in the filename, it scans the first 10 lines of the file.

### 3. Set Output Options

| Field | Default | Description |
|-------|---------|-------------|
| **Output Folder** | `~/Desktop` | Where the `.xlsx` report is saved |
| **Report Name** | `AuditReport_MultiDevice` | Filename (`.xlsx` appended automatically) |

### 4. Run the Audit

Click **▶ Run Audit**. The progress bar activates while files are processed in a background thread — the UI stays responsive. When complete, a summary popup shows:

- Number of devices scanned
- Total findings across all devices
- Report save path

### 5. Review Findings Preview

The **Findings Preview** table shows results inline before you open the Excel file:

| Column | Description |
|--------|-------------|
| `#` | Finding number |
| `Severity` | High / Medium / Low — colour coded |
| `Observation` | Brief description of the finding |
| `Affected Device` | Device IP extracted from the file |

---

## 📊 Output Format

The tool generates a single `.xlsx` workbook with **one sheet per device**, named by IP address.

### Sheet Structure

Each sheet contains the following columns:

| Column | Field | Description |
|--------|-------|-------------|
| A | `#` | Sequential finding number |
| B | `Severity` | High / Medium / Low — colour filled |
| C | `Observation` | Bold title + detail sentence (rich text) |
| D | `Affected Device` | Device IP |
| E | `Description` | What the control does and why it matters |
| F | `Impact` | Business/security risk if not configured |
| G | `Recommendation` | Exact AOS-CX commands to remediate |
| H | `Received Output` | Config lines found in the log (evidence) |
| I | `Expected Output` | What a compliant configuration looks like |
| J | `FSL Remarks` | Free field for reviewer notes |
| K | `EY Remarks` | Free field for secondary reviewer notes |

### Severity Colour Coding

```
🔴  High    →  Red fill    (#FFC7CE)
🟡  Medium  →  Amber fill  (#FFEB9C)
🟢  Low     →  Green fill  (#C6EFCE)
✅  Pass    →  No findings — "All checks PASSED" message on the sheet
```

---

## ⚙️ Requirements

### Python Version

```
Python 3.8 or higher
```

### Dependencies

```bash
pip install openpyxl
```

`tkinter` is included with standard Python on Windows and macOS. On Linux:

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter
```

### Supported Input File Types

The tool accepts any plain-text Aruba AOS-CX configuration export:

```
*.log    *.txt    *.conf
```

---

## 🗂️ Project Structure

```
aruba_audit_tool.py
│
├── AUDIT_CHECKS[]            Knowledge base: 5 checks with severity,
│                             description, impact, recommendation,
│                             expected output, and check function name
│
├── Intent & Pass Patterns    Regex patterns per check:
│   ├── _PWD_INTENT / _PWD_PASS
│   ├── _AAA_INTENT / _AAA_PASS_*
│   ├── _NTP_INTENT / _NTP_PASS_*
│   ├── _SSH_INTENT / _SSH_PASS_*
│   └── _SYSLOG_INTENT / _SYSLOG_PASS
│
├── Check Functions           One function per check, returns
│   └── CHECK_DISPATCH{}      (passed: bool, evidence: list)
│
├── run_audit()               Reads a log file, runs all checks,
│                             returns structured findings list
│
├── write_multi_excel()       Builds the .xlsx workbook,
│   └── _write_sheet()        one sheet per device
│
└── AuditApp (tkinter)        Desktop GUI: file picker, options,
                              progress bar, findings preview table
```

---

## 🔐 Security Notes

- All processing is **local** — no data leaves the machine
- Configuration files are opened in **read-only** mode
- Report filenames are **sanitised** to strip illegal characters
- The audit runs in a **background thread** to keep the UI non-blocking
- The tool is strictly for **review purposes** and does not modify any device configuration

---

<div align="center">

*Built for internal security review of Aruba AOS-CX infrastructure.*
*Part of the Audit Shield security tooling suite.*

</div>
