<div align="center">

# 🔒 Aruba OS Secure Configuration Auditor

**Automated CIS benchmark auditing for HPE Aruba AOS-CX switches**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![CIS Benchmark](https://img.shields.io/badge/CIS-HPE%20Aruba%20CX%20v1.0.1-orange)](https://www.cisecurity.org/)
[![Checks](https://img.shields.io/badge/Audit%20Checks-61-brightgreen)]()
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-blueviolet)]()

<br/>

<br/>

> Upload one or more Aruba AOS-CX switch configuration files and get a fully formatted Excel report in seconds — no cloud, no account, no dependencies beyond Python.

</div>

---

## What it does

This tool reads the plain-text output of `show running-config` from any HPE Aruba AOS-CX switch and evaluates it against **61 security checks** drawn directly from the **CIS HPE Aruba Networking CX Switch Benchmark v1.0.1**.

For every check that fails, the report tells you:

- **What** the CIS finding is and why it matters
- **What was found** in your config (or that the config is missing entirely)
- **Exactly what the config should look like** to pass

The output is a colour-coded Excel workbook — one sheet per device — ready to drop into a security review, a change-management ticket, or a compliance report.

---

## Checks at a glance

61 checks across 4 sections of the CIS Benchmark:

| Section | Topic | Checks |
|---|---|---|
| **1 — Management** | Passwords, SSH, NTP, SNMP, AAA, PKI, HTTPS, Syslog, Banner, Backup, Hostname | 30 |
| **2 — Interface** | USB/Bluetooth, Unused ports, Rate limiting, Proxy ARP, Directed Broadcast | 5 |
| **3 — Protocol** | OSPF, BGP, DHCP snooping, Multicast, ARP inspection, ND snooping, RA Guard, IPv6 | 23 |
| **4 — Control Plane** | CoPP, Spanning Tree BPDU/Root Guard, Control Plane ACLs | 3 |

<details>
<summary>See all 61 checks</summary>

| CIS ID | Check | Severity |
|---|---|---|
| 1.1.3 | Hardening Password Rules | 🔴 High |
| 1.1.4 | Set an Export Password | 🟡 Medium |
| 1.1.8 | Session Management | 🟡 Medium |
| 1.1.9 | Verifying Telnet Server is Disabled | 🔴 High |
| 1.2.1 | SSH Public Key Authentication | 🟡 Medium |
| 1.2.2 | SSH Allow List | 🟡 Medium |
| 1.2.3 | SSH Server Port Customization | 🟢 Low |
| 1.2.5 | Two-factor Authentication with SSH server | 🟡 Medium |
| 1.3.1 | NTP Authentication | 🟡 Medium |
| 1.3.2 | Configuring Time Services | 🟢 Low |
| 1.4.1.1 | Non-Default Community Names, Access Rights & ACL | 🔴 High |
| 1.4.2.1 | SNMP V3 | 🔴 High |
| 1.4.3 | SNMP Traps | 🟢 Low |
| 1.5.1.1 | RADIUS Server Configuration | 🟡 Medium |
| 1.5.1.2 | TACACS Server Configuration | 🟡 Medium |
| 1.5.2.2 | Limit Login Attempts | 🟡 Medium |
| 1.5.2.3 | Remote Authentication — RADIUS/RadSec/TACACS+ | 🟡 Medium |
| 1.5.3.1 | Local Authorization | 🟢 Low |
| 1.5.3.2 | Remote Authorization | 🟡 Medium |
| 1.5.4.1 | Local Accounting | 🟢 Low |
| 1.5.4.2 | Remote Accounting | 🟡 Medium |
| 1.5.6 | Login Privilege Elevation for Administrators | 🟡 Medium |
| 1.6.2 | TLS Minimum Version | 🟡 Medium |
| 1.9.1 | HTTPS-server Default Enablement | 🟢 Low |
| 1.9.2 | HTTPS-server Idle Session Management | 🟢 Low |
| 1.10.1 | ServiceOS Password | 🟡 Medium |
| 1.11.2 | Configure Syslog-client to Log Using TLS | 🟢 Low |
| 1.12 | Login Banner | 🟢 Low |
| 1.13 | Schedule Configuration Backup Job | 🟢 Low |
| 1.14 | Create Hostname | 🟢 Low |
| 2.1.1 | Disable USB and Bluetooth on Device | 🟡 Medium |
| 2.1.3 | Disable Unused Physical Interfaces | 🟡 Medium |
| 2.2 | Traffic Control — Rate Limiting | 🟢 Low |
| 2.3 | Proxy ARP | 🟢 Low |
| 2.4 | IP Directed Broadcast | 🟡 Medium |
| 3.1.1.1 | OSPF Passive Interfaces | 🟢 Low |
| 3.1.1.2 | OSPF Neighbor Authentication | 🟡 Medium |
| 3.1.1.3 | OSPFv3 Area Authentication and Encryption with IPsec | 🟡 Medium |
| 3.1.2.1 | Control Plane ACL for BGP Peering Sessions | 🟡 Medium |
| 3.1.2.2 | Authenticate BGP Peers Using MD5 | 🟡 Medium |
| 3.1.2.3 | BGP TTL Security | 🟢 Low |
| 3.2.1.1 | DHCPv4 & DHCPv6 Snooping Enablement | 🟡 Medium |
| 3.2.1.2 | DHCPv6 Guard | 🟢 Low |
| 3.3.1.1 | PIM Accept-Register | 🟢 Low |
| 3.3.1.2 | PIM Accept-RP | 🟢 Low |
| 3.3.1.3 | PIM SSM | 🟢 Low |
| 3.3.3 | IGMP Snooping ACL | 🟢 Low |
| 3.3.4 | MLD Snooping ACL | 🟢 Low |
| 3.3.5 | MSDP Authentication & SA Filtering | 🟡 Medium |
| 3.3.6 | MSDP SA Cache Limit | 🟢 Low |
| 3.3.7 | Multicast Boundary ACL | 🟢 Low |
| 3.3.8 | Multicast BSR Boundary | 🟢 Low |
| 3.4 | IP Source Lockdown | 🟡 Medium |
| 3.5 | Dynamic ARP Inspection | 🟡 Medium |
| 3.6 | ND Snooping | 🟢 Low |
| 3.7 | RA Guard | 🟢 Low |
| 3.8 | IPv6 Destination Guard | 🟢 Low |
| 4.1.1 | Control Plane Policing | 🟡 Medium |
| 4.2.1 | Spanning Tree BPDU Protect | 🟡 Medium |
| 4.2.2 | Spanning Tree Root Protect | 🟡 Medium |
| 4.3.1 | Control Plane ACL Management | 🔴 High |

</details>

---

## Report output

Every audit produces a `.xlsx` file with one worksheet per scanned device.

| Column | Contents |
|---|---|
| **#** | Finding number |
| **CIS ID** | Benchmark reference (e.g. `1.2.2`, `3.5`) |
| **Severity** | 🔴 High · 🟡 Medium · 🟢 Low — colour-coded cell |
| **Observation** | Bold finding title + full observation sentence |
| **Affected Device** | Device IP (extracted from filename or config) |
| **Description** | Why this control matters |
| **Impact** | Security risk if the control is absent |
| **Recommendation** | Exact remediation commands from the CIS Benchmark |
| **Received Output** | Config lines found in the file (with line numbers), or *Missing Configuration* |
| **Expected Output** | What the correctly configured lines should look like |

If a device passes all 61 checks, its sheet shows a single green row.

---

## Requirements

- Python **3.8** or later
- Works on **Windows**, **macOS**, and **Linux**

```
pip install openpyxl
```

> `tkinter` ships with the standard Python installer on all platforms. If you are on a minimal Linux install and it is missing, install it with `sudo apt install python3-tk` (Debian/Ubuntu) or `sudo dnf install python3-tkinter` (Fedora/RHEL).

---

## Getting started

**1. Clone the repository**

```bash
git clone https://github.com/your-username/aruba-os-auditor.git
cd aruba-os-auditor
```

**2. Install the dependency**

```bash
pip install openpyxl
```

**3. Run the tool**

```bash
python aruba_os_full_audit_tool.py
```

**4. Get a config file from your switch**

On the AOS-CX device:

```
switch# show running-config
```

Copy/save the terminal output as a `.log`, `.txt`, or `.conf` file. For the clearest report, name the file after the device IP — e.g. `192.168.1.10.log`.

**5. Add files and run the audit**

- Click **Add Files** and select one or more config files
- Set the output folder (defaults to your Desktop)
- Give the report a name
- Click **▶ Run Audit**
- The `.xlsx` report appears in your chosen folder automatically

---

## How it works

```
.log / .txt / .conf file
        │
        ▼
  extract_device_ip()          ← reads IP from filename or first 10 lines
        │
        ▼
  run_audit()
    ├── check_password_complexity()
    ├── check_ssh_allowlist()
    ├── check_ntp_auth()
    ├── check_snmpv3()
    ├── ... (61 checks total)
    │
    ▼
  Each check returns (passed: bool, found_lines: list)
        │
        ▼
  _exact_scan()                ← matches only the specific command lines
        │                         derived from the CIS remediation commands.
        │                         No broad keyword matching — only exact hits.
        ▼
  build Received Output        ← "Missing Configuration" or matched lines
  build Expected Output        ← exact remediation commands from the benchmark
        │
        ▼
  write_multi_excel()          ← one sheet per device, colour-coded Excel report
```

Each check function uses **exact regex patterns** anchored to the start of the line (`^\s*`), derived directly from the CIS remediation commands. This means:

- **No false positives** from comment lines or unrelated commands
- **Received Output** shows only the config lines directly relevant to the finding
- **Pass/fail** is determined by whether all required command components are present

---

## Project structure

```
aruba-os-auditor/
├── aruba_os_full_audit_tool.py   # Main script — everything in one file
└── README.md
```

The entire tool is intentionally a single self-contained file. The knowledge base (`AUDIT_CHECKS`), all check functions, the Excel writer, and the GUI all live together — making it easy to read, extend, and share.

---

## Contributing

Contributions of any kind are welcome — new checks, bug fixes, UI improvements, or documentation.

### Adding a new check

Every check follows the same pattern. To add one:

**1. Add an entry to `AUDIT_CHECKS`**

```python
{
    "id": 62,
    "cis_id": "1.x.x",
    "obs_title": "Your Check Title (Automated)",
    "observation": "It was observed that <control> is not configured.",
    "severity": "Medium",          # High | Medium | Low
    "description": "Why this matters...",
    "impact": "What can go wrong if absent...",
    "recommendation": (
        "It is recommended to configure <control>.\n\n"
        "switch(config)# <command>"
    ),
    "expected_output": (
        "switch(config)# <command>"
    ),
    "check_fn": "check_your_control",
},
```

**2. Write the check function**

```python
def check_your_control(lines):
    # Define exact patterns matching the remediation command(s)
    PASS_PATTERNS = [
        r"^\s*<exact-command>\b",
    ]
    # Check if all required patterns are present
    hits = {p: False for p in PASS_PATTERNS}
    for line in lines:
        for p in PASS_PATTERNS:
            if not hits[p] and re.search(p, line, re.IGNORECASE):
                hits[p] = True
    if all(hits.values()):
        return True, []
    # Return False + the matching lines for the Received Output
    return False, _exact_scan(lines, PASS_PATTERNS)
```

**3. Register the function in `CHECK_DISPATCH`**

```python
CHECK_DISPATCH = {
    ...
    "check_your_control": check_your_control,
}
```

That's it — the audit engine, Excel writer, and GUI pick it up automatically.

### Guidelines

- **Pattern accuracy** — Pass patterns should be anchored (`^\s*`) and match only the specific command form from the CIS remediation. Avoid broad keyword patterns that could match unrelated lines.
- **Source** — Check descriptions, impacts, and recommendations should be grounded in the CIS benchmark or a comparable authoritative source. Please note the source in your PR description.
- **One PR per check (or small related group)** — Keeps reviews focused.
- **Test with real config files** — Include a brief note in the PR describing what you tested against (a sanitised snippet is ideal).
- **No breaking changes to the data structure** — The `AUDIT_CHECKS` dict keys and `CHECK_DISPATCH` interface are stable. New keys can be added but existing ones should not be renamed.

### Reporting issues

Found a check that produces a false positive, misses a valid finding, or has incorrect remediation commands? Please open an issue with:

- The CIS ID and check name
- A short sanitised snippet of the config that triggers the problem
- What the tool reported vs. what you expected

---

## Acknowledgements

- **[Center for Internet Security (CIS)](https://www.cisecurity.org/)** — CIS HPE Aruba Networking CX Switch Benchmark v1.0.1, which defines all 61 controls implemented here.
- **[HPE Aruba Networking](https://www.arubanetworks.com/)** — AOS-CX platform and documentation.
- **[openpyxl](https://openpyxl.readthedocs.io/)** — Excel report generation.

---

<div align="center">
<sub>Built for the network security community · Contributions welcome · Not affiliated with HPE or CIS</sub>
</div>
