import xml.etree.ElementTree as ET
import csv
import argparse
import sys

def parse_nmap(xml_file, csv_file=None):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML: {e}")
        return

    headers = ['IP', 'Port', 'Protocol', 'Overall_Grade', 'SWEET32_Found']
    rows = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr') if host.find('address') is not None else "Unknown"
        
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            script = port.find('script[@id="ssl-enum-ciphers"]')
            if script is None: continue

            for proto_table in script.findall('table'):
                proto_name = proto_table.get('key')
                
                # Get the grade for this protocol
                grade_elem = proto_table.find("elem[@key='grade']")
                grade = grade_elem.text if grade_elem is not None else "N/A"
                
                # Check if ANY cipher in this protocol uses 3DES
                has_sweet32 = "No"
                cipher_list = proto_table.find('table[@key="ciphers"]')
                if cipher_list is not None:
                    for cipher in cipher_list.findall('table'):
                        for e in cipher.findall('elem'):
                            if e.get('key') == 'name' and "3DES" in e.text:
                                has_sweet32 = "YES"
                                break
                
                rows.append([ip, port_id, proto_name, grade, has_sweet32])

    if csv_file:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"[*] Success: Report saved to {csv_file}")
    else:
        if not rows:
            print("No SSL data found.")
            return

        # Terminal table formatting
        col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
        format_str = "  ".join(["{:<" + str(w) + "}" for w in col_widths])
        
        print("\n" + format_str.format(*headers))
        print("-" * (sum(col_widths) + (len(headers) * 2)))
        for row in rows:
            # Highlight YES in red for terminal visibility
            display_row = list(row)
            if display_row[4] == "YES":
                display_row[4] = f"\033[91m{display_row[4]}\033[0m"
            print(format_str.format(*display_row))
        print("")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize Nmap SSL Protocols.")
    parser.add_argument("input", help="The Nmap XML file")
    parser.add_argument("-o", "--output", help="Output to CSV file")
    
    args = parser.parse_args()
    parse_nmap(args.input, args.output)
