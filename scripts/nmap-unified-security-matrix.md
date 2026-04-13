# NMAP Unified Security Matrix

A unified Python utility that parses Nmap XML results from:

- `ssl-cert`
- `ssl-enum-ciphers`
- `rdp-enum-encryption`

It merges findings into a single host/port row and produces one report output (terminal table or single CSV).

## Features

- **Single Tool, Single Report**: Combines three Nmap NSE script outputs into one consolidated matrix.
- **Multi-Input Support**: Accepts one or more XML files in a single run.
- **Merge by Target Socket**: Correlates records using **IP + Port**.
- **No External Dependencies**: Uses only Python 3 standard libraries.
- **Colorized Terminal Output**: Highlights detection results for fast triage.
- **CSV Export**: Exports one UTF-8 BOM CSV for Excel compatibility.

## Supported Inputs

Use XML files generated with Nmap `-oX` or `-oA`from any of these scripts:

- `rdp-enum-encryption`
- `ssl-cert`
- `ssl-enum-ciphers`

You can pass one XML or multiple XML files at once.

## Output Columns

| Column | Description |
|---|---|
| IP / Port | Target location used as merge key. |
| Subject / Issuer | Parsed from `ssl-cert` output. |
| Untrusted | `YES` if self-signed or marked not trustable. |
| Self-Signed | `YES` if Subject == Issuer. |
| Weak Hash | `YES` for MD5/SHA1 signatures. |
| Wrong Host | `YES` / `no` / `Undetermined` based on hostname match clues. |
| Weak RSA Key | `YES` if key size is below 2048 bits. |
| Max Protocol | Highest protocol seen in `ssl-enum-ciphers`. |
| SSLv3 / TLSv1.0 / TLSv1.1 / TLSv1.2 | `YES` if protocol is observed enabled. |
| SWEET32 / Bar Mitzvah / POODLE | `YES` if matching Nmap warning text is present. |
| RDP Version | Value parsed from `RDP Protocol Version`. |
| Enc Level | Value parsed from `RDP Encryption Level`. |
| Med/Low Enc | RDP encryption-level rank check (details below). |
| Non-NLA Only | `YES` if `Native RDP: SUCCESS` or `SSL: SUCCESS` exists. |
| Non-FIPS | `no` only when encryption level is exactly `FIPS Compliant`. |
| MITM Risk | Derived from RDP version + Non-NLA + Non-FIPS. |

## RDP Detection Logic

### 1) Encryption Level (`Enc Level`)

Parses text after `RDP Encryption Level`.

### 2) Med/Low Enc

Rank mapping:

- `None` = 0
- `Low` = 1
- `Client Compatible` = 2
- `High` = 3
- `FIPS Compliant` = 4

Result:

- `YES` if rank is `< 3`
- `no` if rank is `>= 3`
- `Undetermined` if not available/unknown

### 3) Non-NLA Only

- `YES` if `Native RDP: SUCCESS` **or** `SSL: SUCCESS` is present
- `no` otherwise
- `Undetermined` when the Security Layer block is missing

### 4) Non-FIPS

- `no` **only if** encryption level is exactly `FIPS Compliant`
- `YES` for any other known encryption level
- `Undetermined` if unavailable

### 5) MITM Risk

- `YES`: old RDP version (`5.x/6.x/7.x/8.x`) + Non-NLA=`YES` + Non-FIPS=`YES`
- `High Likely`: old version + one of those vulnerable
- `Low Chance`: modern version + one of those vulnerable
- `No`: modern version + neither vulnerable
- `Undetermined`: insufficient data

## Usage

### 1. Generate XML files

Run Nmap with one or more scripts and save XML output (`-oX`).

### 2. Run unified parser

Terminal output:

```bash
python3 nmap-unified-security-matrix.py rdp.xml ssl-cert.xml ssl-ciphers.xml
```

CSV output:

```bash
python3 nmap-unified-security-matrix.py rdp.xml ssl-cert.xml ssl-ciphers.xml -o unified-report.csv
```

Single-input mode (also supported):

```bash
python3 nmap-unified-security-matrix.py rdp.xml -o rdp-only.csv
```

## Notes

- If a script section is absent for a host/port, unrelated columns remain `-`.
- If XML parsing fails for one input file, the tool continues processing other files.
- Final output is always one consolidated report.
