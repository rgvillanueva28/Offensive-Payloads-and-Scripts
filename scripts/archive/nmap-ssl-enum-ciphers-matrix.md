# NMAP ssl-enum-ciphers Matrix

A lightweight Python utility to convert complex Nmap `ssl-enum-ciphers` XML output into a clean, actionable compliance matrix. This tool helps auditors quickly identify which protocols are enabled and which specific vulnerabilities are present across a network.

## Features
* **Protocol Support Matrix:** Tracks individual support for SSLv3, TLSv1.0, TLSv1.1, and TLSv1.2.
* **Max Protocol Identification:** Automatically determines the strongest available protocol version.
* **Vulnerability Mapping:** Specifically scans for SWEET32, Bar Mitzvah (RC4), and POODLE based on official Nmap warning strings.
* **Terminal Formatting:** Perfectly aligned columns in the terminal with color-coded "YES" flags for rapid risk assessment.
* **CSV Export:** Generate spreadsheet-ready reports via the `-o` flag.

## Extracted Columns

>**NOTE**: Detections are what is observed only based on scan data of the developer. Do not rely solely on this tool if there are observed additional detection methods.

| Column Title | Detection / Logic |
| :--- | :--- |
| **IP / Port** | Target identification. |
| **Max Protocol** | The highest protocol version successfully negotiated. |
| **SSLv3 to TLSv1.2** | Boolean (YES/No) support for each specific protocol version. |
| **SWEET32** | Found warning: `64-bit block cipher 3DES vulnerable to SWEET32 attack`. |
| **Bar Mitzvah** | Found warning: `Broken cipher RC4 is deprecated by RFC 7465`. |
| **POODLE** | Found warning: `CBC-mode cipher in SSLv3 (CVE-2014-3566)`. |

## Usage

### 1. Generate Nmap XML
Run your scan and ensure you use the `-oX` flag to create the required XML input:
```bash
nmap -p 443,1433,3389 --script ssl-enum-ciphers -oX scan_results.xml <target>

```

### 2. Run the Parser

**To display the table in the terminal:**

```bash
python3 nmap-ssl-enum-ciphers-matrix.py scan_results.xml

```

**To export to a CSV file:**

```bash
python3 nmap-ssl-enum-ciphers-matrix.py scan_results.xml -o audit_report.csv

```

## Example Output

The script ensures that even with ANSI colors enabled, the columns remain strictly aligned.

| IP | Port | Max Protocol | SSLv3 | TLSv1.0 | TLSv1.1 | TLSv1.2 | SWEET32 | Bar Mitzvah | POODLE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 111.123.18.15 | 1433 | TLSv1.0 | YES | YES | No | No | YES | YES | YES |
| 111.123.18.15 | 3389 | TLSv1.2 | No | YES | YES | YES | YES | YES | No |

---
