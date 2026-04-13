# NMAP ssl-cert Matrix

A Python-based utility to parse Nmap XML script `ssl-cert` scan results and generate a clear security posture matrix. This tool helps security auditors and system administrators quickly identify common SSL/TLS misconfigurations.

## Features

- **No Dependencies**: Uses only Python 3 standard libraries (no `pip install` required).
- **Automated XML Parsing**: Efficiently extracts SSL certificate data from Nmap `-oX` output.
- **Security Matrix Generation**: Provides a high-level overview of multiple security checks in a single view.
- **Colorized Terminal Output**: Uses ANSI escape codes to highlight vulnerabilities (**YES** in Red, **NO** in Green) for fast triage.
- **CSV Export**: Supports saving results to a CSV file with UTF-8 BOM encoding for seamless viewing in Microsoft Excel.
- **Dynamic Table Alignment**: Automatically adjusts column widths based on content for perfect terminal readability.
- **Zero-Emoji Compatibility**: Uses standard ASCII "YES/NO" text to ensure the table remains perfectly aligned in all environments.
    

## Extracted Columns

The tool evaluates and displays the following data points:

|   |   |
|---|---|
|**Column**|**Description**|
|**IP / Port**|The network location of the service.|
|**Subject**|The identity claimed by the certificate.|
|**Issuer**|The authority that signed the certificate.|
|**Untrusted**|Flagged **YES** if the CA is unknown or the certificate is self-signed.|
|**Self-Signed**|Flagged **YES** if the Subject and Issuer are identical.|
|**Weak Hash**|Flagged **YES** if the signature algorithm uses MD5 or SHA-1.|
|**Wrong Host**|Based on Nmap logic: **YES** (mismatch), **NO** (match), or **Undetermined**.|
|**Weak RSA Key**|Flagged **YES** if the RSA public key is less than 2048 bits.|

## Requirements

The script requires only **Python 3.x**. No external libraries are needed.

## Usage

### 1. Generate Nmap Data

First, scan your targets using Nmap with the `ssl-cert` script and save the output to XML:

```
nmap -p 443,8443,1433 --script ssl-cert <target_ip_or_range> -oX scan_results.xml
```

### 2. Run the Tool

Display the results in your terminal:

```
python3 nmap-ssl-cert-matrix.py scan_results.xml
```

Export the results to a CSV file:

```
python3 nmap-ssl-cert-matrix.py scan_results.xml -o report.csv
```

## Example Output

### Terminal Display

The terminal output uses color-coded status indicators:

- **RED (YES)**: Security vulnerability or misconfiguration detected.
- **GREEN (NO)**: Configuration meets common security standards.
- **YELLOW (Undetermined)**: Insufficient data found in the certificate to make a determination.
    

```
==================================================================================================================================
IP                Port  Subject                    Issuer                     Untrusted  Self-Signed  Weak Hash  Wrong Host    Weak RSA Key
----------------------------------------------------------------------------------------------------------------------------------
192.168.1.50      443   https://www.example.com)            DigiCert TLS RSA SHA256    NO         NO           NO         NO            NO
192.168.1.105     1433  SSL_Self_Signed_Fallback   SSL_Self_Signed_Fallback   YES        YES          NO         Undetermined  NO
10.0.0.12         8443  Internal_Dev_Srv           Internal_Dev_Srv           YES        YES          YES        YES           YES
==================================================================================================================================
```
