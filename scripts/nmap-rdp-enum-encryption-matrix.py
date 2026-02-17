import xml.etree.ElementTree as ET
import csv
import sys
import argparse

# Standard ANSI escape sequences for terminal colors (No external library required)
# These work on Linux, macOS, and modern Windows terminals.
CLR_RESET = "\033[0m"
CLR_BOLD  = "\033[1m"

# Unique color per distinct result value
CLR_YES        = "\033[1;31m"   # Bold Red       -- YES (vulnerable)
CLR_NO         = "\033[1;32m"   # Bold Green     -- no (safe)
CLR_UNDET      = "\033[1;36m"   # Bold Cyan      -- Undetermined

CLR_MITM_YES   = "\033[1;31m"   # Bold Red       -- MITM: YES
CLR_MITM_HIGH  = "\033[1;35m"   # Bold Magenta   -- MITM: High Likely
CLR_MITM_LOW   = "\033[1;33m"   # Bold Yellow    -- MITM: Low Chance
CLR_MITM_NO    = "\033[1;32m"   # Bold Green     -- MITM: No
CLR_MITM_UNDET = "\033[1;36m"   # Bold Cyan      -- MITM: Undetermined


def get_color_vuln(val):
    """Returns colored string for YES / no / Undetermined vulnerability fields."""
    if val == "YES":
        return f"{CLR_YES}{val}{CLR_RESET}"
    elif val == "no":
        return f"{CLR_NO}{val}{CLR_RESET}"
    elif val == "Undetermined":
        return f"{CLR_UNDET}{val}{CLR_RESET}"
    return val


def get_color_mitm(val):
    """Returns colored string for MITM risk -- each level has a unique colour."""
    if val == "YES":
        return f"{CLR_MITM_YES}{val}{CLR_RESET}"
    elif val == "High Likely":
        return f"{CLR_MITM_HIGH}{val}{CLR_RESET}"
    elif val == "Low Chance":
        return f"{CLR_MITM_LOW}{val}{CLR_RESET}"
    elif val == "No":
        return f"{CLR_MITM_NO}{val}{CLR_RESET}"
    elif val == "Undetermined":
        return f"{CLR_MITM_UNDET}{val}{CLR_RESET}"
    return val


def parse_rdp_encryption(xml_file, output_csv=None):
    """
    Parses Nmap XML for rdp-enum-encryption script output and produces
    an RDP security vulnerability matrix.

    Real output format (&#xa; = newline, entries indented with spaces):
      Security layer                        <- header line, NO colon
        CredSSP (NLA): SUCCESS
        Native RDP: SUCCESS
        SSL: SUCCESS
      RDP Encryption level: Client Compatible  <- colon on header line
        40-bit RC4: SUCCESS
        FIPS 140-1: SUCCESS
      RDP Protocol Version:  RDP 5.x, 6.x, 7.x, or 8.x server

    Checks performed:
      1. Med/Low Enc   – Encryption Level is not 'High' or 'FIPS Compliant'
      2. Non-NLA Only  – Security layer accepts 'Native RDP' or 'SSL' (not NLA-only)
      3. Non-FIPS      – Encryption Level is not exactly 'FIPS Compliant'
      4. MITM Risk     – Derived from RDP version + NLA + FIPS findings
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return

    results = []

    for host in root.findall('host'):
        # Get IP address safely
        ip_node = host.find('address[@addrtype="ipv4"]')
        if ip_node is None:
            ip_node = host.find('address')
        ip = ip_node.get('addr') if ip_node is not None else "Unknown"

        for port_node in host.findall('.//port'):
            port = port_node.get('portid')
            script = port_node.find("script[@id='rdp-enum-encryption']")

            if script is None:
                continue  # Skip ports without the rdp-enum-encryption script

            output = script.get('output', '')

            # ----------------------------------------------------------------
            # Guard: unhandled / error responses (e.g. "Received unhandled packet")
            # ----------------------------------------------------------------
            output_stripped = output.strip()
            if not output_stripped or '\n' not in output_stripped:
                # Single-line output means no structured data was returned
                results.append({
                    "IP":           ip,
                    "Port":         port,
                    "RDP Version":  "N/A",
                    "Enc Level":    "N/A",
                    "Med/Low Enc":  "Undetermined",
                    "Non-NLA Only": "Undetermined",
                    "Non-FIPS":     "Undetermined",
                    "MITM Risk":    "Undetermined",
                    "_raw_note":    output_stripped[:60],
                })
                continue

            # Split into raw lines, preserving leading whitespace for indent detection
            raw_lines = output.splitlines()

            # ----------------------------------------------------------------
            # Parse structured blocks by indentation level
            #
            # Top-level headers have 2-space indent (or none after the leading \n).
            # Child entries have 4-space indent.
            # We detect blocks by finding header keywords and collecting the
            # indented lines that follow until the next same-level header.
            # ----------------------------------------------------------------

            # Normalise: strip the leading blank line the script output starts with
            raw_lines = [l for l in raw_lines if l.strip()]  # drop blank lines

            # Determine indent of the first real line to establish "top-level" indent
            def indent_of(line):
                return len(line) - len(line.lstrip())

            # Collect lines with their indent levels
            parsed = [(indent_of(l), l.strip()) for l in raw_lines]

            # ---- Identify top-level indent (smallest indent among all lines) ----
            top_indent_level = min(ind for ind, _ in parsed) if parsed else 0

            # ---- Walk lines and extract sections ----
            security_children = []   # child lines under "Security layer"
            enc_level_value   = ""   # value after colon on "RDP Encryption level:" line
            rdp_version       = ""   # value after colon on "RDP Protocol Version:" line

            in_security = False
            in_enc      = False

            for i, (ind, text) in enumerate(parsed):
                text_lower = text.lower()

                if ind == top_indent_level:
                    # New top-level entry — reset section flags
                    in_security = False
                    in_enc      = False

                    if text_lower == "security layer":
                        # Header with NO colon — children follow on subsequent lines
                        in_security = True

                    elif text_lower.startswith("rdp encryption level:"):
                        # Header WITH colon — value is on the same line
                        enc_level_value = text.split(":", 1)[1].strip()
                        in_enc = True   # child lines follow (RC4, FIPS entries) — we don't need them

                    elif text_lower.startswith("rdp protocol version:"):
                        rdp_version = text.split(":", 1)[1].strip()

                else:
                    # Child line
                    if in_security:
                        security_children.append(text_lower)
                    # (enc children like "40-bit RC4: SUCCESS" are ignored)

            # ================================================================
            # VULNERABILITY 1: Encryption Level Medium or Low
            # Safe values: 'High' or 'FIPS Compliant'
            # ================================================================
            if not enc_level_value:
                enc_med_low = "Undetermined"
            elif enc_level_value.lower() in ("high", "fips compliant"):
                enc_med_low = "no"
            else:
                enc_med_low = "YES"

            # ================================================================
            # VULNERABILITY 2: Doesn't Use NLA Only
            # Vulnerable if Security layer accepts Native RDP or plain SSL
            # (i.e. non-NLA methods succeed).
            # Note: "ssl: success" in the security layer children is the trigger,
            # NOT the RDSTLS or CredSSP entries.
            # ================================================================
            has_security_section = bool(security_children)
            security_text = " ".join(security_children)

            # Check for the vulnerable entries (strip SUCCESS/FAILURE noise)
            native_rdp_success = any("native rdp: success" in l for l in security_children)
            ssl_success        = any(
                l.startswith("ssl:") and "success" in l
                for l in security_children
            )

            if not has_security_section:
                non_nla = "Undetermined"
            elif native_rdp_success or ssl_success:
                non_nla = "YES"
            else:
                non_nla = "no"

            # ================================================================
            # VULNERABILITY 3: Not FIPS-140 Compliant
            # Only 'FIPS Compliant' passes.
            # ================================================================
            if not enc_level_value:
                non_fips = "Undetermined"
            elif enc_level_value.lower() == "fips compliant":
                non_fips = "no"
            else:
                non_fips = "YES"

            # ================================================================
            # VULNERABILITY 4: MITM Risk
            #
            # old_rdp = "RDP 5.x, 6.x, 7.x, or 8.x server" in version string
            #
            # YES         – old version AND Non-NLA AND Non-FIPS
            # High Likely – old version AND (Non-NLA OR Non-FIPS)
            # Low Chance  – NOT old version AND (Non-NLA OR Non-FIPS)
            # No          – NOT old version AND NOT Non-NLA AND NOT Non-FIPS
            # Undetermined – ambiguous due to missing data
            # ================================================================
            old_rdp    = "rdp 5.x, 6.x, 7.x, or 8.x server" in rdp_version.lower()

            nla_vuln   = (non_nla  == "YES")
            fips_vuln  = (non_fips == "YES")
            nla_undet  = (non_nla  == "Undetermined")
            fips_undet = (non_fips == "Undetermined")

            if old_rdp:
                if nla_vuln and fips_vuln:
                    mitm_risk = "YES"
                elif nla_vuln or fips_vuln:
                    mitm_risk = "High Likely"
                elif nla_undet or fips_undet:
                    mitm_risk = "Undetermined"
                else:
                    mitm_risk = "Low Chance"
            else:
                if nla_vuln or fips_vuln:
                    mitm_risk = "Low Chance"
                elif nla_undet or fips_undet:
                    mitm_risk = "Undetermined"
                else:
                    mitm_risk = "No"

            results.append({
                "IP":           ip,
                "Port":         port,
                "RDP Version":  rdp_version if rdp_version else "Unknown",
                "Enc Level":    enc_level_value if enc_level_value else "Unknown",
                "Med/Low Enc":  enc_med_low,
                "Non-NLA Only": non_nla,
                "Non-FIPS":     non_fips,
                "MITM Risk":    mitm_risk,
                "_raw_note":    "",
            })

    if not results:
        print("No rdp-enum-encryption data found in the provided XML.")
        return

    # Public-facing columns (strip the internal _raw_note key)
    keys = ["IP", "Port", "RDP Version", "Enc Level", "Med/Low Enc", "Non-NLA Only", "Non-FIPS", "MITM Risk"]
    vuln_keys = {"Med/Low Enc", "Non-NLA Only", "Non-FIPS"}

    # Build clean rows for output (without _raw_note)
    clean_results = [{k: r[k] for k in keys} for r in results]

    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(clean_results)
        print(f"[*] Report successfully saved to: {output_csv}")
    else:
        # Dynamic column widths based on content
        widths = {
            k: max(len(k), max((len(str(r[k])) for r in clean_results), default=0)) + 2
            for k in keys
        }
        # Cap long free-text columns
        for k in ["RDP Version", "Enc Level"]:
            widths[k] = min(widths[k], 42)

        total_width = sum(widths.values())
        sep = "=" * total_width

        print(f"\n{sep}")
        header_line = "".join(f"{k:<{widths[k]}}" for k in keys)
        print(f"{CLR_BOLD}{header_line}{CLR_RESET}")
        print("-" * total_width)

        for r, raw in zip(clean_results, results):
            line = ""
            for k in keys:
                raw_val = str(r[k])

                # Truncate long free-text columns
                max_w = widths[k] - 3
                if k in ("RDP Version", "Enc Level") and len(raw_val) > max_w:
                    raw_val = raw_val[:max_w - 2] + "..."

                # Apply colour
                if k in vuln_keys:
                    display_val = get_color_vuln(raw_val)
                elif k == "MITM Risk":
                    display_val = get_color_mitm(raw_val)
                else:
                    display_val = raw_val

                padding = " " * (widths[k] - len(raw_val))
                line += display_val + padding

            print(line)

        print(f"{sep}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RDP Security Matrix – parses Nmap rdp-enum-encryption script output"
    )
    parser.add_argument("input", help="Nmap XML output file (-oX)")
    parser.add_argument("-o", "--output", help="Optional: save report as CSV")

    args = parser.parse_args()
    parse_rdp_encryption(args.input, args.output)