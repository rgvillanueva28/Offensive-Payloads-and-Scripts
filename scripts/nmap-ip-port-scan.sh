#!/bin/bash

# Define Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

if [ "$#" -lt 2 ]; then
    echo -e "${RED}Usage:${NC} $0 <targets_file> \"<nmap_args>\""
    exit 1
fi

INPUT_FILE=$1
EXTRA_ARGS=$2

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}   Multi-Port Nmap Script Runner${NC}"
echo -e "${BLUE}========================================${NC}"

while read -r line || [ -n "$line" ]; do
    # Skip empty lines or comments
    [[ -z "$line" || "$line" == \#* ]] && continue

    # Parse the line: first word is target, the rest are ports
    read -r target raw_ports <<< "$line"

    # Convert spaces in ports to commas
    formatted_ports=$(echo $raw_ports | tr ' ' ',')

    if [ -z "$formatted_ports" ]; then
        echo -e "${RED}[!] Skipping:${NC} No ports defined for $target"
        continue
    fi

    # Construct the full command string for display
    FULL_COMMAND="nmap -p $formatted_ports $EXTRA_ARGS $target"

    echo -e "${GREEN}[+] Target:${NC} $target"
    echo -e "${YELLOW}[+] Ports :${NC} $formatted_ports"
    echo -e "${MAGENTA}[>] Running:${NC} ${FULL_COMMAND}"
    
    # Execute the actual command
    eval $FULL_COMMAND

    echo -e "${BLUE}----------------------------------------${NC}"

done < "$INPUT_FILE"

echo -e "${GREEN}Scan complete!${NC}"
