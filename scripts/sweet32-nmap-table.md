## Nmap SWEET32 Table

A lightweight Python tool to convert complex, nested Nmap XML scan results into a clean, high-level summary table. It is specifically designed to identify **SWEET32** vulnerabilities and weak SSL/TLS protocols during security audits.

---

### Features

* **Aggregated View:** Collapses long lists of ciphers into a simple "one row per protocol" summary.
* **SWEET32 Detection:** Automatically flags any protocol offering 64-bit block ciphers (3DES).
* **Dual Output:** * **Terminal:** Prints a beautifully aligned, color-coded table for quick analysis.
* **CSV:** Generates a flat file for spreadsheets and reporting via the `-o` flag.


* **Zero Dependencies:** Uses standard Python libraries (no `pip install` required).

---

### Usage

#### 1. Generate Scan Data

First, run your Nmap scan and ensure you output to **XML** format:

```bash
nmap -p 443,1433,3389 --script ssl-enum-ciphers -oX scan_results.xml <target>

```

#### 2. Run the Auditor

**To view results immediately in the terminal:**

```bash
python3 sweet32-nmap-table.py scan_results.xml

```

**To export results to a CSV file for Excel:**

```bash
python3 sweet32-nmap-table.py scan_results.xml -o audit_report.csv

```

---

### Sample Output

| IP | Port | Protocol | Overall_Grade | SWEET32_Found |
| --- | --- | --- | --- | --- |
| 111.123.18.15 | 1433 | SSLv3 | F | **YES** |
| 111.123.18.15 | 3389 | TLSv1.2 | F | **YES** |
| 192.168.1.50 | 443 | TLSv1.2 | A | No |

---
