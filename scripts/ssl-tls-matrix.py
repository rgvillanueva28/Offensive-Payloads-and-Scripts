import xml.etree.ElementTree as ET
import csv
import argparse
import re

def get_visible_len(text):
    """Calculates length of string without ANSI escape codes."""
    return len(re.sub(r'\033\[[0-9;]*m', '', str(text)))

def get_protocol_weight(proto):
    """Assigns numerical weight to protocols for comparison."""
    weights = {'SSLv2': 1, 'SSLv3': 2, 'TLSv1.0': 3, 'TLSv1.1': 4, 'TLSv1.2': 5, 'TLSv1.3': 6}
    return weights.get(proto.replace(" ", ""), 0)

def parse_nmap_matrix(xml_file, csv_file=None):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML: {e}")
        return

    headers = ['IP', 'Port', 'Max Protocol', 'SWEET32', 'Bar Mitzvah', 'POODLE']
    rows = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr') if host.find('address') is not None else "Unknown"
        
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            script = port.find('script[@id="ssl-enum-ciphers"]')
            if script is None: continue

            port_data = {h: "No" for h in headers}
            port_data.update({'IP': ip, 'Port': port_id, 'Max Protocol': 'None'})
            
            current_max_weight = -1

            for proto_table in script.findall('table'):
                proto_name = proto_table.get('key')
                
                weight = get_protocol_weight(proto_name)
                if weight > current_max_weight:
                    current_max_weight = weight
                    port_data['Max Protocol'] = proto_name

                warn_table = proto_table.find('table[@key="warnings"]')
                if warn_table is not None:
                    for warning in warn_table.findall('elem'):
                        text = warning.text
                        if "64-bit block cipher 3DES vulnerable to SWEET32 attack" in text:
                            port_data['SWEET32'] = "YES"
                        if "Broken cipher RC4 is deprecated by RFC 7465" in text:
                            port_data['Bar Mitzvah'] = "YES"
                        if "CBC-mode cipher in SSLv3 (CVE-2014-3566)" in text:
                            port_data['POODLE'] = "YES"

            rows.append([port_data[h] for h in headers])

    if csv_file:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"[*] Report saved to {csv_file}")
    else:
        formatted_rows = []
        for row in rows:
            new_row = []
            for i, val in enumerate(row):
                if val == "YES":
                    new_row.append(f"\033[91m{val}\033[0m")
                else:
                    new_row.append(val)
            formatted_rows.append(new_row)

        widths = []
        for i, h in enumerate(headers):
            max_w = len(h)
            for row in formatted_rows:
                v_len = get_visible_len(row[i])
                if v_len > max_w: max_w = v_len
            widths.append(max_w)

        header_line = "  ".join(f"{headers[i]:<{widths[i]}}" for i in range(len(headers)))
        print("\n" + header_line)
        print("-" * (sum(widths) + (len(headers) * 2)))

        for row in formatted_rows:
            line = []
            for i, val in enumerate(row):
                padding = widths[i] - get_visible_len(val)
                line.append(str(val) + (" " * padding))
            print("  ".join(line))
        print("")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    parse_nmap_matrix(args.input, args.output)
