import argparse
import csv
import re
import xml.etree.ElementTree as ET

# Standard ANSI escape sequences for terminal colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[1;31m"
CLR_GREEN = "\033[1;32m"
CLR_CYAN = "\033[1;36m"
CLR_YELLOW = "\033[1;33m"
CLR_MAGENTA = "\033[1;35m"


def visible_len(text):
    """Length without ANSI escape codes."""
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def color_yes_no_undet(val):
    if val == "YES":
        return f"{CLR_RED}{val}{CLR_RESET}"
    if val == "no":
        return f"{CLR_GREEN}{val}{CLR_RESET}"
    if val == "Undetermined":
        return f"{CLR_CYAN}{val}{CLR_RESET}"
    return val


def color_mitm(val):
    if val == "YES":
        return f"{CLR_RED}{val}{CLR_RESET}"
    if val == "High Likely":
        return f"{CLR_MAGENTA}{val}{CLR_RESET}"
    if val == "Low Chance":
        return f"{CLR_YELLOW}{val}{CLR_RESET}"
    if val == "No":
        return f"{CLR_GREEN}{val}{CLR_RESET}"
    if val == "Undetermined":
        return f"{CLR_CYAN}{val}{CLR_RESET}"
    return val


def get_protocol_weight(proto):
    weights = {
        "SSLv2": 1,
        "SSLv3": 2,
        "TLSv1.0": 3,
        "TLSv1.1": 4,
        "TLSv1.2": 5,
        "TLSv1.3": 6,
    }
    return weights.get(proto.replace(" ", ""), 0)


def parse_ssl_cert(script_output):
    """Parse ssl-cert script output into findings."""
    untrusted, self_signed, weak_hash, hostname_mismatch, weak_keys = (
        "no",
        "no",
        "no",
        "Undetermined",
        "no",
    )
    subj_val, issuer_val = "Unknown", "Unknown"

    raw_lower = script_output.lower()
    lines = [line.strip() for line in script_output.split("\n")]

    raw_subject = next((l for l in lines if l.lower().startswith("subject:")), "")
    raw_issuer = next((l for l in lines if l.lower().startswith("issuer:")), "")
    sig_algo = next((l for l in lines if l.lower().startswith("signature algorithm:")), "").lower()
    pk_bits_line = next((l for l in lines if l.lower().startswith("public key bits:")), "")

    subj_val = raw_subject.replace("Subject: ", "") if raw_subject else "Unknown"
    issuer_val = raw_issuer.replace("Issuer: ", "") if raw_issuer else "Unknown"

    if subj_val != "Unknown" and subj_val == issuer_val:
        self_signed = "YES"
        untrusted = "YES"
    elif "not trustable" in raw_lower:
        untrusted = "YES"

    if any(x in sig_algo for x in ["md5", "sha1"]):
        weak_hash = "YES"

    has_hostname_info = "commonname" in raw_lower or "subjectaltname" in raw_lower
    if "does not match" in raw_lower:
        hostname_mismatch = "YES"
    elif has_hostname_info:
        hostname_mismatch = "no"

    if pk_bits_line:
        try:
            bits = int("".join(filter(str.isdigit, pk_bits_line)))
            if bits < 2048:
                weak_keys = "YES"
        except ValueError:
            weak_keys = "Undetermined"

    return {
        "Subject": subj_val,
        "Issuer": issuer_val,
        "Untrusted": untrusted,
        "Self-Signed": self_signed,
        "Weak Hash": weak_hash,
        "Wrong Host": hostname_mismatch,
        "Weak RSA Key": weak_keys,
    }


def parse_ssl_enum_ciphers(script_node):
    """Parse ssl-enum-ciphers table node into findings."""
    result = {
        "Max Protocol": "None",
        "SSLv3": "no",
        "TLSv1.0": "no",
        "TLSv1.1": "no",
        "TLSv1.2": "no",
        "SWEET32": "no",
        "Bar Mitzvah": "no",
        "POODLE": "no",
    }

    current_max_weight = -1

    for proto_table in script_node.findall("table"):
        key = proto_table.get("key") or ""
        proto_name = key.replace(" ", "")

        if proto_name in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"):
            result[proto_name] = "YES"

        weight = get_protocol_weight(proto_name)
        if weight > current_max_weight:
            current_max_weight = weight
            result["Max Protocol"] = proto_name or "None"

        warn_table = proto_table.find('table[@key="warnings"]')
        if warn_table is not None:
            for warning in warn_table.findall("elem"):
                text = (warning.text or "").strip()
                if "64-bit block cipher 3DES vulnerable to SWEET32 attack" in text:
                    result["SWEET32"] = "YES"
                if "Broken cipher RC4 is deprecated by RFC 7465" in text:
                    result["Bar Mitzvah"] = "YES"
                if "CBC-mode cipher in SSLv3 (CVE-2014-3566)" in text:
                    result["POODLE"] = "YES"

    return result


def parse_rdp_enum_encryption(script_output):
    """Parse rdp-enum-encryption output into findings."""
    out = (script_output or "").strip()

    if not out or "\n" not in out:
        return {
            "RDP Version": "N/A",
            "Enc Level": "N/A",
            "Med/Low Enc": "Undetermined",
            "Non-NLA Only": "Undetermined",
            "Non-FIPS": "Undetermined",
            "MITM Risk": "Undetermined",
        }

    raw_lines = [l for l in script_output.splitlines() if l.strip()]

    def indent_of(line):
        return len(line) - len(line.lstrip())

    parsed = [(indent_of(l), l.strip()) for l in raw_lines]
    top_indent_level = min(ind for ind, _ in parsed) if parsed else 0

    security_children = []
    enc_level_value = ""
    rdp_version = ""

    in_security = False

    for ind, text in parsed:
        text_lower = text.lower()

        if ind == top_indent_level:
            in_security = False

            if text_lower == "security layer":
                in_security = True
            elif text_lower.startswith("rdp encryption level:"):
                enc_level_value = text.split(":", 1)[1].strip()
            elif text_lower.startswith("rdp protocol version:"):
                rdp_version = text.split(":", 1)[1].strip()
        else:
            if in_security:
                security_children.append(text_lower)

    if not enc_level_value:
        enc_med_low = "Undetermined"
    elif enc_level_value.lower() in ("high", "fips compliant"):
        enc_med_low = "no"
    else:
        enc_med_low = "YES"

    has_security_section = bool(security_children)
    native_rdp_success = any("native rdp: success" in l for l in security_children)
    ssl_success = any(l.startswith("ssl:") and "success" in l for l in security_children)

    if not has_security_section:
        non_nla = "Undetermined"
    elif native_rdp_success or ssl_success:
        non_nla = "YES"
    else:
        non_nla = "no"

    if not enc_level_value:
        non_fips = "Undetermined"
    elif enc_level_value.lower() == "fips compliant":
        non_fips = "no"
    else:
        non_fips = "YES"

    old_rdp = "rdp 5.x, 6.x, 7.x, or 8.x server" in rdp_version.lower()
    nla_vuln = non_nla == "YES"
    fips_vuln = non_fips == "YES"
    nla_undet = non_nla == "Undetermined"
    fips_undet = non_fips == "Undetermined"

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

    return {
        "RDP Version": rdp_version if rdp_version else "Unknown",
        "Enc Level": enc_level_value if enc_level_value else "Unknown",
        "Med/Low Enc": enc_med_low,
        "Non-NLA Only": non_nla,
        "Non-FIPS": non_fips,
        "MITM Risk": mitm_risk,
    }


def make_base_row(ip, port):
    return {
        "IP": ip,
        "Port": port,
        "Subject": "-",
        "Issuer": "-",
        "Untrusted": "-",
        "Self-Signed": "-",
        "Weak Hash": "-",
        "Wrong Host": "-",
        "Weak RSA Key": "-",
        "Max Protocol": "-",
        "SSLv3": "-",
        "TLSv1.0": "-",
        "TLSv1.1": "-",
        "TLSv1.2": "-",
        "SWEET32": "-",
        "Bar Mitzvah": "-",
        "POODLE": "-",
        "RDP Version": "-",
        "Enc Level": "-",
        "Med/Low Enc": "-",
        "Non-NLA Only": "-",
        "Non-FIPS": "-",
        "MITM Risk": "-",
    }


def parse_unified_matrix(xml_files):
    merged = {}

    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except Exception as e:
            print(f"Error parsing XML '{xml_file}': {e}")
            continue

        for host in root.findall("host"):
            ip_node = host.find('address[@addrtype="ipv4"]')
            if ip_node is None:
                ip_node = host.find("address")
            ip = ip_node.get("addr") if ip_node is not None else "Unknown"

            for port_node in host.findall(".//port"):
                port = port_node.get("portid") or "Unknown"

                ssl_cert_script = port_node.find("script[@id='ssl-cert']")
                ssl_ciphers_script = port_node.find("script[@id='ssl-enum-ciphers']")
                rdp_script = port_node.find("script[@id='rdp-enum-encryption']")

                if ssl_cert_script is None and ssl_ciphers_script is None and rdp_script is None:
                    continue

                key = (ip, port)
                if key not in merged:
                    merged[key] = make_base_row(ip, port)

                if ssl_cert_script is not None:
                    merged[key].update(parse_ssl_cert(ssl_cert_script.get("output", "")))

                if ssl_ciphers_script is not None:
                    merged[key].update(parse_ssl_enum_ciphers(ssl_ciphers_script))

                if rdp_script is not None:
                    merged[key].update(parse_rdp_enum_encryption(rdp_script.get("output", "")))

    return list(merged.values())


def print_table(rows, headers):
    vuln_cols = {
        "Untrusted",
        "Self-Signed",
        "Weak Hash",
        "Wrong Host",
        "Weak RSA Key",
        "SSLv3",
        "TLSv1.0",
        "TLSv1.1",
        "TLSv1.2",
        "SWEET32",
        "Bar Mitzvah",
        "POODLE",
        "Med/Low Enc",
        "Non-NLA Only",
        "Non-FIPS",
    }

    width_caps = {
        "Subject": 30,
        "Issuer": 30,
        "RDP Version": 42,
        "Enc Level": 24,
    }

    widths = {}
    for h in headers:
        max_len = len(h)
        for r in rows:
            val = str(r.get(h, ""))
            cap = width_caps.get(h)
            if cap is not None and len(val) > cap - 3:
                val = val[: cap - 6] + "..."
            if len(val) > max_len:
                max_len = len(val)
        widths[h] = max_len + 2

    total_width = sum(widths.values())
    sep = "=" * total_width

    print(f"\n{sep}")
    header_line = "".join(f"{h:<{widths[h]}}" for h in headers)
    print(f"{CLR_BOLD}{header_line}{CLR_RESET}")
    print("-" * total_width)

    for r in rows:
        line = ""
        for h in headers:
            raw_val = str(r.get(h, ""))
            cap = width_caps.get(h)
            if cap is not None and len(raw_val) > cap - 3:
                raw_val = raw_val[: cap - 6] + "..."

            if h in vuln_cols:
                display_val = color_yes_no_undet(raw_val)
            elif h == "MITM Risk":
                display_val = color_mitm(raw_val)
            else:
                display_val = raw_val

            pad = widths[h] - visible_len(raw_val)
            line += display_val + (" " * pad)

        print(line)

    print(f"{sep}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Unified Nmap matrix for ssl-cert + ssl-enum-ciphers + rdp-enum-encryption"
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more Nmap XML files (e.g. rdp-enum-encryption.xml ssl-cert.xml ssl-enum-ciphers.xml)",
    )
    parser.add_argument("-o", "--output", help="Optional: save one unified CSV report")
    args = parser.parse_args()

    rows = parse_unified_matrix(args.inputs)
    if not rows:
        print("No relevant script data found in the provided XML.")
        return

    headers = [
        "IP",
        "Port",
        "Subject",
        "Issuer",
        "Untrusted",
        "Self-Signed",
        "Weak Hash",
        "Wrong Host",
        "Weak RSA Key",
        "Max Protocol",
        "SSLv3",
        "TLSv1.0",
        "TLSv1.1",
        "TLSv1.2",
        "SWEET32",
        "Bar Mitzvah",
        "POODLE",
        "RDP Version",
        "Enc Level",
        "Med/Low Enc",
        "Non-NLA Only",
        "Non-FIPS",
        "MITM Risk",
    ]

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[*] Unified report saved to: {args.output}")
    else:
        print_table(rows, headers)


if __name__ == "__main__":
    main()
