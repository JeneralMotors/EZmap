# EZmap - Network Enumeration Script

## Overview

EZmap is a Bash script designed for network enumeration, providing a streamlined process for scanning and gathering information about hosts on a network. It leverages the power of Nmap for host discovery, port scanning, and service identification, and it includes functionality for extracting and displaying open ports, services, and potential vulnerabilities.

## Features

- **Multi-Host Mode:** Perform network discovery on a specified IP range, scanning multiple hosts.
- **Single-Host Mode:** Scan a single specified IP address for detailed information.
- **Automatic Port Scanning:** Utilize Nmap for comprehensive port scanning.
- **Service Identification:** Run service scans to identify running services on open ports.
- **Vulnerability Detection:** Identify potential vulnerabilities using Nmap scripts.

## Prerequisites

- [Nmap](https://nmap.org/) must be installed on the system.

## Usage

### Single-Host Mode
```bash
sudo ezmap 192.168.1.1
```

### Multi-Host Mode
```bash
sudo ezmap 192.168.1.0/24
```
