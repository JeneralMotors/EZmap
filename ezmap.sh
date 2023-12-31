#!/bin/bash

# Color variables for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
# Reset colors
NC='\033[0m'

# Check if the script is running with UID 0 (root)
if [ "$(id -u)" -ne 0 ]; then
    printf "\n${ORANGE}This script must be run as root. Exiting...${NC}\n\n"
    exit 1
fi

# Check if an IP address or range is provided as an argument
if [ -z "$1" ]; then
    printf "\n${ORANGE}Usage: $0 <ip or ip range>${NC}\n"
    printf "${ORANGE}Example: $0 192.168.1.1 or $0 192.168.1.0/24${NC}\n\n"
    exit 1
fi

# Function to handle CTRL+C
ctrl_c() {
    printf "\n${ORANGE}CTRL+C received. Exiting...${NC}\n"
    # Show cursor
    tput cnorm
    exit 1
}

# Set up trap to call ctrl_c function on CTRL+C
trap ctrl_c INT

# Hide cursor
tput civis

# Function to perform nmap scan
perform_nmap_scan() {
    local ip=$1
    local output_dir=$2

    printf "${GREEN}[+] STARTING${NC} nmap ${BLUE}INITIAL SCAN${NC} scan for ${BLUE}HOST ($ip)${NC}...\n"
    nmap -sS -n -Pn -p- --min-rate 2000 --open $ip -oN $output_dir > /dev/null 2>&1
}

# Function to perform nmap service scan
perform_nmap_servscan() {
    local ip=$1
    local ports=$2  # Pass ports as an argument
    local output_dir=$3

    printf "${GREEN}[+] STARTING${NC} nmap ${BLUE}SERVICE SCAN${NC} for ${BLUE}HOST ($ip)${NC}...\n"
    nmap -sCV --script vulners -Pn -n -p$ports $ip -oN $output_dir > /dev/null 2>&1
}

# Function to extract open ports
extract_open_ports() {
    local input_file=$1
    cat $input_file | grep -oP "^[0-9]+" | paste -sd ','
}

# Function to display open ports
display_open_ports() {
    local input_file=$1
    printf "\n${GREEN}[+]${NC} ${BLUE}PORTS${NC} ${GREEN}OPEN${NC} on ${BLUE}HOST ($ip)${NC}:\n\n"
    cat $input_file | grep -E "^[0-9]+" | awk '{print ($1, $3)}' | tr '/' '\t\t' | tr ' ' '\t\t'
    printf "\n"
}

# Iterate through IP range if provided
ip_range=$1
if [[ $ip_range =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+) ]]; then
    network_address=${BASH_REMATCH[1]}
    subnet_mask=${BASH_REMATCH[2]}
    printf "\n${GREEN}[+]${NC} ${ORANGE}MULTI HOST MODE${NC}\n"
    printf "\n${GREEN}[+] STARTING${NC} ${BLUE}HOST DISCOVERY${NC} on ${BLUE}$ip_range${NC}\n"
    # Perform host discovery on the network
    nmap -sP -PS -PR $ip_range -oG - | grep "Up" | cut -d ' ' -f 2 > alive_hosts.txt
    printf "\n${GREEN}[+]${NC} ${BLUE}HOSTS${NC} on ${BLUE}$ip_range${NC}\n\n"
    cat alive_hosts.txt | tr '\n' '\t'
    printf "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
    # Iterate through each IP and perform the scan
    while IFS= read -r ip; do
        mkdir -p nmap/$ip
        perform_nmap_scan $ip nmap/$ip/initial
        ports=$(extract_open_ports nmap/$ip/initial)
        display_open_ports nmap/$ip/initial

        if [ -n "$ports" ]; then
            perform_nmap_servscan $ip $ports nmap/$ip/services  # Pass ports as an argument
            printf "\n${GREEN}[+]${NC} ${BLUE}SERVICES${NC} ${GREEN}RUNNING${NC} on ${BLUE}HOST ($ip)${NC}:\n\n"
            cat nmap/$ip/services | grep -P '^\d+\/\w+' | awk '{print $1, substr($0, index($0,$4))}' | sed 's/\/tcp//;s/\/udp//' | sed 's/ /\t\t/'
            printf "\n${GREEN}[+]${NC} ${RED}POSSIBLE${NC} ${BLUE}CVE's${NC} and ${BLUE}CNVD's${NC}\n\n"
            grep -oP 'CVE-\d{4}-\d+|CNVD-\d{4}-\d+' nmap/"$ip"/services | uniq | sort
            printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
        else
            printf "\n${RED}[!]${NC} No ${BLUE}open ports${NC} found on ${BLUE}HOST ($ip)${NC}\n"
            printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        fi
    done < alive_hosts.txt
else
    # Single IP provided, perform scan
    ip=$1  # Update the variable assignment
    mkdir -p nmap
    printf "\n${GREEN}[+]${NC} ${ORANGE}SINGLE HOST MODE${NC}\n\n"
    perform_nmap_scan $ip nmap/initial
    ports=$(extract_open_ports nmap/initial)
    display_open_ports nmap/initial

    if [ -n "$ports" ]; then
        perform_nmap_servscan $ip $ports nmap/services  # Pass ports as an argument
        printf "\n${GREEN}[+]${NC} ${BLUE}SERVICES RUNNING${NC} on ${BLUE}HOST ($ip)${NC}:\n\n"
        cat nmap/services | grep -P '^\d+\/\w+' | awk '{print $1, substr($0, index($0,$4))}' | sed 's/\/tcp//;s/\/udp//' | sed 's/ /\t\t/'
        printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"

        printf "\n${GREEN}[+]${NC} ${RED}POSSIBLE${NC} ${BLUE}CVE's${NC} and ${BLUE}CNVD's${NC}\n\n"
        grep -oP 'CVE-\d{4}-\d+|CNVD-\d{4}-\d+' nmap/services | uniq | sort
    else
        printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        printf "\n${RED}[!]${NC} No ${BLUE}open ports${NC} found on ${BLUE}HOST ($ip)${NC}.\n"
        printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    fi
fi

# Show cursor
tput cnorm
