import sys
import nmap

def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-p 1-65535 --open -sS -n -Pn -sV')  # Added -sV for service version detection
    
    for host in scanner.all_hosts():
        print(f"Open ports for {host}:")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service_name = scanner[host][proto][port]['name']
                service_state = scanner[host][proto][port]['state']
                service_product = scanner[host][proto][port]['product']
                service_version = scanner[host][proto][port]['version']
                
                print(f"Port {port}: {service_name} - {service_state}")
                print(f"  Service: {service_product} {service_version}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    scan_ports(target_ip)
