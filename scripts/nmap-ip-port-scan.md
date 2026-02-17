# Per-Asset Nmap Script Runner

A flexible Bash utility designed to bypass Nmap's limitation of scanning specific ports for specific assets when using an input list. This script allows you to define unique IP/Port pairs and apply a global set of Nmap arguments and scripts to each.

## Features
* **Granular Control:** Specify exactly which port to scan for each individual host.
* **Argument Injection:** Pass any standard Nmap flags (e.g., `-sV`, `--script`, `-Pn`) through the command line.
* **Comment Support:** Supports `#` comments and empty lines in your target list.

## Prerequisites
* **Nmap** installed and available in your PATH.
* **Linux/macOS** (or WSL on Windows).

## File Structure

### 1. Target List (`targets.txt`)
The input file should contain the target (IP or Hostname) followed by a space and the port number.

```text
192.168.1.10       80
192.168.1.15       443
api.example.com    8443 8080 8081
10.0.0.5           22
```

### 2. The Script (`nmap-ip-port-scan.sh`)

Ensure the script has execution permissions:

```bash
chmod +x nmap-ip-port-scan.sh

```

## Usage

Run the script by providing the target file and your desired Nmap arguments inside **quotes**.

```bash
./nmap-ip-port-scan.sh <targets_file> "<nmap_arguments>"

```

### Examples

**Basic script scan:**

```bash
./nmap-ip-port-scan.sh targets.txt "-sC"

```

**Service detection with specific scripts and no ping:**

```bash
./nmap-ip-port-scan.sh targets.txt "-sV --script http-auth-finder -Pn"

```

**Aggressive scan with output saved to an XML file:**

```bash
./nmap-ip-port-scan.sh targets.txt "-A -T4 -oX output.xml"

```

## How It Works

The script reads the input file line-by-line, splitting the host and port into variables. It then constructs and executes a custom Nmap command for each line:
`nmap -p <port> <your_args> <target>`
