# SSL/TLS Matrix Nmap Parser

A lightweight Python utility to convert complex Nmap `ssl-enum-ciphers` XML output into a clean, actionable compliance matrix. This tool identifies the highest supported protocol and flags specific cryptographic vulnerabilities based on official Nmap warning strings.

## Features
* **Max Protocol Identification:** Automatically determines the strongest available protocol (e.g., TLSv1.2, TLSv1.3).
* **Vulnerability Mapping:** Specifically scans for SWEET32, Bar Mitzvah (RC4), and POODLE.
* **Terminal Formatting:** Perfectly aligned columns in the terminal, even with color highlighting.
* **CSV Export:** Generate spreadsheet-ready reports for audits.

## Extracted Columns

| Column Title | Nmap Detection / Logic |
| :--- | :--- |
| **IP** | Target IP address. |
| **Port** | Target port number. |
| **Max Protocol** | Highest negotiated protocol version. |
| **SWEET32** | Found: `64-bit block cipher 3DES vulnerable to SWEET32 attack` |
| **Bar Mitzvah** | Found: `Broken cipher RC4 is deprecated by RFC 7465` |
| **POODLE** | Found: `CBC-mode cipher in SSLv3 (CVE-2014-3566)` |

## Usage

### 1. Generate Nmap XML
Run your scan and ensure you use the `-oX` flag:
```bash
nmap -p 443,1433,3389 --script ssl-enum-ciphers -oX scan_results.xml <target>

```

### 2. Run the Parser

**To display the table in the terminal:**

```bash
python3 ssl-tls-matrix.py scan_results.xml

```

**To export to a CSV file:**

```bash
python3 ssl-tls-matrix.py scan_results.xml -o audit_report.csv

```

## Example Output

| IP | Port | Max Protocol | SWEET32 | Bar Mitzvah | POODLE |
| --- | --- | --- | --- | --- | --- |
| 111.123.18.15 | 1433 | TLSv1.0 | YES | YES | YES |
| 111.123.18.15 | 3389 | TLSv1.2 | YES | YES | No |

---
