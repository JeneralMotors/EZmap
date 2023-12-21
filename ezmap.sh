#!/bin/bash

# Check if the script is running with UID 0 (root)
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting..."
    exit 1
fi

# Check if an IP address is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <ip>"
    echo "Example: $0 192.168.1.1"
    exit 1
fi

# Hide cursor
tput civis

# Color variables for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
# Reset colors
NC='\033[0m'

# Assign the provided IP address to a variable
ip=$1
# Create a directory to store nmap scan results
mkdir -p nmap

# Display paths for initial and service results
printf "\n${GREEN}[+]${NC} ${BLUE}INITIAL${NC} results will be saved on ${CYAN}$(pwd)/nmap/initial${NC}\n"
printf "${GREEN}[+]${NC} ${BLUE}SERVICE${NC} results will be saved on ${CYAN}$(pwd)/nmap/services${NC}\n\n"
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"

# Initial scan using nmap
printf "${GREEN}STARTING${NC} nmap ${BLUE}INITIAL${NC} scan...\n"
nmap -sS -n -Pn -p- --min-rate 2000 --open $ip -oN $(pwd)/nmap/initial > /dev/null 2>&1

# Extract open ports using regular expressions
ports=$(cat $(pwd)/nmap/initial | grep -oP "^[0-9]+" | paste -sd ',')

# Display open ports on the screen
printf "\n${GREEN}[+]${NC} ${BLUE}PORTS OPEN${NC} on ${BLUE}HOST ($ip)${NC}:\n\n"
cat $(pwd)/nmap/initial | grep -E "^[0-9]+" | awk '{print ($1, $3)}' | tr '/' '\t\t' | tr ' ' '\t\t'
printf "\n"

# Check if there are open ports before running the second scan
if [ -z "$ports" ]; then
    printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    printf "\n${RED}[!] No${NC} ${BLUE}open ports${NC} found.\n"
    printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    exit 0
fi
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"

# Detailed scan for open ports
printf "\n${GREEN}STARTING${NC} nmap ${BLUE}SERVICE${NC} scan...\n"
nmap -sCV --script vulners -Pn -n -p$ports $ip -oN $(pwd)/nmap/services > /dev/null 2>&1

printf "\n${GREEN}[+]${NC} ${BLUE}SERVICES RUNNING${NC} on ${BLUE}HOST ($ip)${NC}:\n\n"
# Display services running on open ports
cat $(pwd)/nmap/services | grep -P '^\d+\/\w+' | awk '{print $1, substr($0, index($0,$4))}' | sed 's/\/tcp//;s/\/udp//' | sed 's/ /\t\t/'
printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"

# Display the services file
printf "\n${GREEN}[+]${NC} Possible ${BLUE}CVE's${NC} and ${BLUE}CNVD's${NC}\n\n"
cat $(pwd)/nmap/services | grep -oP 'CVE-\d{4}-\d+|CNVD-\d{4}-\d+' | uniq | sort

# Show cursor
tput cnorm
