import xml.etree.ElementTree as ET
import csv
import sys
import argparse

# Standard ANSI escape sequences for terminal colors (No external library required)
# These work on Linux, macOS, and modern Windows terminals.
CLR_RED = "\033[1;31m"
CLR_GREEN = "\033[0;32m"
CLR_YELLOW = "\033[0;33m"
CLR_BOLD = "\033[1m"
CLR_RESET = "\033[0m"

def get_color_val(val):
    """Returns colored string using standard ANSI codes."""
    if val == "YES":
        return f"{CLR_RED}{val}{CLR_RESET}"
    elif val == "no":
        return f"{CLR_GREEN}{val}{CLR_RESET}"
    elif val == "Undetermined":
        return f"{CLR_YELLOW}{val}{CLR_RESET}"
    return val

def parse_nmap_matrix(xml_file, output_csv=None):
    """Parses Nmap XML and outputs a security matrix using only built-in libraries."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return

    results = []
    
    for host in root.findall('host'):
        # Get IP address safely (explicit None check to avoid DeprecationWarning)
        ip_node = host.find('address[@addrtype="ipv4"]')
        if ip_node is None:
            ip_node = host.find('address')
        
        ip = ip_node.get('addr') if ip_node is not None else "Unknown"
        
        for port_node in host.findall('.//port'):
            port = port_node.get('portid')
            script = port_node.find("script[@id='ssl-cert']")
            
            # Default audit values
            untrusted, self_signed, weak_hash, hostname_mismatch, weak_keys = "no", "no", "no", "Undetermined", "no"
            subj_val, issuer_val = "N/A", "N/A"
            
            if script is not None:
                output = script.get('output', '')
                raw_lower = output.lower()
                lines = [line.strip() for line in output.split('\n')]
                
                # Extraction of raw fields
                raw_subject = next((l for l in lines if l.lower().startswith("subject:")), "")
                raw_issuer = next((l for l in lines if l.lower().startswith("issuer:")), "")
                sig_algo = next((l for l in lines if l.lower().startswith("signature algorithm:")), "").lower()
                pk_bits_line = next((l for l in lines if l.lower().startswith("public key bits:")), "")
                
                subj_val = raw_subject.replace("Subject: ", "") if raw_subject else "Unknown"
                issuer_val = raw_issuer.replace("Issuer: ", "") if raw_issuer else "Unknown"
                
                # 1 & 2. Trust/Self-Signed Logic
                if subj_val != "Unknown" and subj_val == issuer_val:
                    self_signed = "YES"
                    untrusted = "YES"
                elif "not trustable" in raw_lower:
                    untrusted = "YES"
                
                # 3. Weak Hash Logic
                if any(x in sig_algo for x in ["md5", "sha1"]):
                    weak_hash = "YES"
                
                # 4. Hostname Logic
                has_hostname_info = "commonname" in raw_lower or "subjectaltname" in raw_lower
                if "does not match" in raw_lower:
                    hostname_mismatch = "YES"
                elif has_hostname_info:
                    hostname_mismatch = "no"
                
                # 5. Weak RSA Keys Check (< 2048 bits)
                if pk_bits_line:
                    try:
                        bits = int(''.join(filter(str.isdigit, pk_bits_line)))
                        if bits < 2048:
                            weak_keys = "YES"
                    except ValueError:
                        weak_keys = "Undetermined"

                results.append({
                    "IP": ip,
                    "Port": port,
                    "Subject": subj_val,
                    "Issuer": issuer_val,
                    "Untrusted": untrusted,
                    "Self-Signed": self_signed,
                    "Weak Hash": weak_hash,
                    "Wrong Host": hostname_mismatch,
                    "Weak RSA Key": weak_keys
                })

    if not results:
        print("No SSL certificate data found in the provided XML.")
        return

    keys = ["IP", "Port", "Subject", "Issuer", "Untrusted", "Self-Signed", "Weak Hash", "Wrong Host", "Weak RSA Key"]

    if output_csv:
        # Excel-friendly CSV output with UTF-8 BOM
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"[*] Report successfully saved to: {output_csv}")
    else:
        # Calculate dynamic widths based on content for perfect alignment
        widths = {k: max(len(k), max((len(str(r[k])) for r in results), default=0)) + 2 for k in keys}
        for k in ["Subject", "Issuer"]: 
            widths[k] = min(widths[k], 25) # Cap long DNs

        sep = "=" * sum(widths.values())
        print(f"\n{sep}")
        
        # Print Header (Bold)
        header_line = "".join([f"{k:<{widths[k]}}" for k in keys])
        print(f"{CLR_BOLD}{header_line}{CLR_RESET}")
        print("-" * sum(widths.values()))

        # Print Rows
        for r in results:
            line = ""
            for k in keys:
                raw_val = str(r[k])
                # Truncate long Subject/Issuer
                if k in ["Subject", "Issuer"] and len(raw_val) > (widths[k] - 3):
                    raw_val = raw_val[:widths[k]-5] + "..."
                
                # Apply color if security indicator
                if k in ["Untrusted", "Self-Signed", "Weak Hash", "Wrong Host", "Weak RSA Key"]:
                    display_val = get_color_val(raw_val)
                else:
                    display_val = raw_val
                
                # Calculate padding manually to account for non-printable ANSI characters
                padding = " " * (widths[k] - len(raw_val))
                line += display_val + padding
            print(line)
            
        print(f"{sep}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSL Security Matrix (No dependencies required)")
    parser.add_argument("input", help="The XML file generated by Nmap (using -oX)")
    parser.add_argument("-o", "--output", help="Optional: Path to save the report as a CSV file")
    
    args = parser.parse_args()
    parse_nmap_matrix(args.input, args.output)