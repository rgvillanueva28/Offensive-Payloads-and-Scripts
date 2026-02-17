# NMAP rdp-enum-encryption Matrix

A Python-based utility to parse Nmap XML script `rdp-enum-encryption` scan results and generate a clear security posture matrix. This tool helps security auditors and system administrators quickly identify common RDP misconfigurations and assess exposure to man-in-the-middle attacks.

## Features

- **No Dependencies**: Uses only Python 3 standard libraries (no `pip install` required).
- **Automated XML Parsing**: Efficiently extracts RDP encryption and authentication data from Nmap `-oX` output.
- **Security Matrix Generation**: Provides a high-level overview of multiple security checks in a single view.
- **Colorized Terminal Output**: Uses ANSI escape codes to highlight each result with a unique color for fast triage.
- **CSV Export**: Supports saving results to a CSV file with UTF-8 BOM encoding for seamless viewing in Microsoft Excel.
- **Dynamic Table Alignment**: Automatically adjusts column widths based on content for perfect terminal readability.
- **Graceful Error Handling**: Hosts that return unstructured output (e.g., `Received unhandled packet`) are still included with `N/A` and `Undetermined` values rather than being silently skipped.

## Extracted Columns

The tool evaluates and displays the following data points:

| **Column** | **Description** |
|---|---|
| **IP / Port** | The network location of the RDP service. |
| **RDP Version** | The RDP protocol version string reported by the server. |
| **Enc Level** | The raw encryption level value reported (e.g., `Client Compatible`, `High`, `FIPS Compliant`). |
| **Med/Low Enc** | Flagged **YES** if the encryption level is anything other than `High` or `FIPS Compliant`. |
| **Non-NLA Only** | Flagged **YES** if the server accepts `Native RDP` or plain `SSL` — meaning NLA is not enforced exclusively. |
| **Non-FIPS** | Flagged **YES** if the encryption level is not exactly `FIPS Compliant`. |
| **MITM Risk** | Derived risk rating based on RDP version, NLA enforcement, and FIPS compliance (see logic below). |

## MITM Risk Logic

The **MITM Risk** column is calculated from the combination of RDP protocol version and the two authentication/encryption vulnerability flags:

| **Result** | **Condition** |
|---|---|
| **YES** | Old RDP protocol (`5.x / 6.x / 7.x / 8.x`) **AND** both Non-NLA and Non-FIPS are vulnerable. |
| **High Likely** | Old RDP protocol **AND** either Non-NLA **or** Non-FIPS is vulnerable. |
| **Low Chance** | Modern RDP protocol **AND** either Non-NLA **or** Non-FIPS is vulnerable. |
| **No** | Modern RDP protocol **AND** neither Non-NLA nor Non-FIPS is vulnerable. |
| **Undetermined** | Insufficient data to make a determination. |

## Usage

### 1. Generate Nmap Data

First, scan your targets using Nmap with the `rdp-enum-encryption` script and save the output to XML:

```
nmap -p 3389 --script rdp-enum-encryption <target_ip_or_range> -oX scan_results.xml
```

### 2. Run the Tool

Display the results in your terminal:

```
python3 nmap-rdp-enum-encryption-matrix.py scan_results.xml
```

Export the results to a CSV file:

```
python3 nmap-rdp-enum-encryption-matrix.py scan_results.xml -o report.csv
```

## Example Output

### Terminal Display

The terminal output uses unique color-coded status indicators per value:

```
================================================================================================================================
IP             Port  RDP Version                       Enc Level          Med/Low Enc   Non-NLA Only  Non-FIPS      MITM Risk
--------------------------------------------------------------------------------------------------------------------------------
155.120.8.15   3389  RDP 5.x, 6.x, 7.x, or 8.x ser...  Client Compati...  YES           YES           YES           YES
155.120.9.40   3389  RDP 10.2 server                   Unknown            Undetermined  YES           Undetermined  Low Chance
155.120.8.244  3389  N/A                               N/A                Undetermined  Undetermined  Undetermined  Undetermined
================================================================================================================================
```

### CSV Export

The CSV output uses UTF-8 BOM encoding and contains the same columns without color codes, making it compatible with Microsoft Excel and other spreadsheet tools.