import argparse
import nmap
import ipaddress
import sys

def expand_ip_range(ip_range):
    try:
        # Expands a given IP range in CIDR notation to a list of individual IP addresses
        ip_list = [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
        return ip_list
    except ValueError as e:
        print(f"Error expanding IP range: {e}")
        sys.exit(1)

def scan_target(target):
    try:
        # Create a Nmap object
        nm = nmap.PortScanner()

        # Perform a host discovery using multiple methods (-sn for ping scan, -PR for ARP ping)
        nm.scan(target, arguments='-sn -PR')

        # Iterate through discovered hosts and perform a detailed port scan
        for host in nm.all_hosts():
            print(f"Host: {host}")
            # Perform a detailed port scan on the discovered host
            nm.scan(host, arguments='-p 1-1000')

            # Print information about open ports on the host
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port}, State: {nm[host][proto][port]['state']}")
    except nmap.PortScannerError as e:
        print(f"Nmap scan error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        # Create an ArgumentParser object to handle command-line arguments
        parser = argparse.ArgumentParser(description="Nmap Scanner with Host Discovery")

        # Add a required argument for the target IP address, range, or CIDR notation
        parser.add_argument("target", help="Specify an IP address, range, or CIDR notation to scan")

        # Parse the command-line arguments
        args = parser.parse_args()
        target = args.target

        # If the input is in CIDR notation, expand it to a list of individual IP addresses
        if '/' in target:
            ip_list = expand_ip_range(target)

            # Scan each individual IP address in the expanded list
            for ip in ip_list:
                scan_target(ip)
        else:
            # If the input is a single IP address or range, scan it directly
            scan_target(target)
    except argparse.ArgumentError as e:
        print(f"Argument error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
