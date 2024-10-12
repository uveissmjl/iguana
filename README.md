# iguana: A Network Analysis Suite

```
⢀⣤⠴⠖⠋⠉⠓⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣄⠀⠂⠀⢶⣿⣇⡙⠷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⢳⡝⠢⡀⠀⠁⠀⠙⠦⣈⢻⡄⠀⠀⠀⠀⣠⢖⣶⡶⠶⠚⠛⠉⣉⠭⠝⠛⠋⠉⠉⠉⠛⠛⠓⠒⠶⠤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⣦⠈⠲⠄⣀⠀⢾⡏⠑⠿⡦⣤⣴⠞⠛⢉⣁⣀⠠⠤⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠓⠶⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠈⠳⣄⡀⠀⠙⢓⡆⠠⢲⢾⣖⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡔⠀⢦⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣄⠀⠀
⠀⠀⠀⠀⠀⠀⠉⢳⣦⣿⣷⣾⣿⡿⢏⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠀⣗⠛⠋⠉⠉⠉⠙⠛⠒⠶⢤⣄⡀⠀⠀⠈⢳⡄
⠀⠀⠀⠀⠀⠀⠀⡾⢅⣻⡟⢛⡏⠁⠃⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠓⢦⠀⠈⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣄⠀⢸⢻
⠀⠀⠀⠀⠀⠀⡼⠁⠀⡇⠑⠧⣌⡉⠉⠑⣌⡉⠋⠛⠛⠶⠶⠶⠶⠶⢋⡴⠃⠀⠈⣷⣤⠟⣒⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣦⠆⣸
⠀⠀⢀⣀⣀⣸⠁⢀⡞⠁⠀⠀⠀⠉⠳⣄⠀⠙⢶⠶⠤⣤⣀⣠⡴⠞⠋⠀⠀⠀⠀⢇⣷⣄⣾⣝⣧⡀⠀⠀⠀⠀⠀⢀⣀⡴⠟⢁⡴⠃
⠀⢸⢷⠯⡽⡋⠀⡚⡇⠀⠀⠀⠀⠀⠀⠈⡆⠀⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⣿⠻⡇⠹⡇⣀⣤⠴⠒⣛⣉⡥⠴⠚⠉⠀⠀
⠀⠸⢹⡿⠤⠲⣾⠗⠃⠀⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⣴⡿⠿⠛⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⠀⠀⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣴⣾⡛⣧⡄⠀⣿⡀⠀⠀⠀⠀Developed by @uveissmjl⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣟⡿⠭⣥⢚⣨⣤⡽⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠀⠸⣞⠉⠀⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

## Overview

**iguana** is an open-source, Python-based tool designed for network enthusiasts, cybersecurity professionals, and students interested in learning and performing comprehensive network analysis. With a set of integrated functionalities, **iguana** enables users to inspect and audit networks with ease, making it a valuable tool for troubleshooting, diagnostics, and ethical hacking.

The tool is perfect for:
- **Discovering active devices** on a network.
- **Identifying open ports** and assessing network security.
- **Capturing and analyzing network traffic**.
- **Gathering DNS information** for reconnaissance.

### Why iguana?
Whether you are troubleshooting a network, auditing the security of a system, or learning about network protocols, **iguana** offers a user-friendly approach without compromising on depth and utility. iguana is intended for **ethical use** and educational purposes.

---

## Features

### 1. **Network Scanning**
- Discover devices on a local network.
- Perform quick scans to identify active IPs and associated MAC addresses.

### 2. **Port Scanning**
- Scan for open ports to identify potential vulnerabilities.
- Analyze services running on specific devices within your network.

### 3. **Network Sniffing**
- Capture network packets on a specified interface for analysis.
- Useful for troubleshooting network issues and examining network traffic patterns.

### 4. **DNS Gathering**
- Retrieve DNS records such as A, MX, NS, and TXT for a given domain.
- Great for reconnaissance and understanding domain infrastructure.

### 5. **Geo-IP Lookup**
- Find the geolocation of a specific IP address using external APIs.
- Identify the location of devices or web servers around the globe.

### 6. **Vulnerability Check**
- Check for open, vulnerable ports such as FTP (21), SSH (22), HTTP (80), and others.
- Helps in assessing the security state of your network devices.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/uveissmjl/iguana
   ```
2. Navigate to the cloned directory:
   ```bash
   cd iguana
   ```
3. Install the required Python libraries:
   ```bash
   pip install scapy dnspython requests
   ```
4. Make the script executable (optional):
   ```bash
   chmod +x iguana.py
   ```

---

## Usage

You can access various features of **iguana** through command-line options. Below are examples of usage for each feature:

### 1. **Network Scanning**
   Discover active devices on the network by scanning an IP range:
   ```bash
   sudo python3 iguana.py -m scan --ip 192.168.1.0/24
   ```

### 2. **Port Scanning**
   Scan for open ports on a specific device:
   ```bash
   sudo python3 iguana.py -m port-scan --ip 192.168.1.1
   ```

### 3. **Network Sniffing**
   Capture and analyze network traffic on a specific network interface:
   ```bash
   sudo python3 iguana.py -m sniff --interface eth0
   ```

### 4. **DNS Gathering**
   Collect detailed DNS information for a domain:
   ```bash
   python3 iguana.py -m dns-gather --domain example.com
   ```

### 5. **Geo-IP Lookup**
   Find the geolocation of a given IP address:
   ```bash
   python3 iguana.py -m geo-ip --ip 8.8.8.8
   ```

### 6. **Vulnerability Check**
   Check for vulnerabilities by scanning well-known ports on a device:
   ```bash
   python3 iguana.py -m vuln-check --ip 192.168.1.1
   ```

---

## Legal Disclaimer

This tool is designed for **legal and ethical use**. Users are required to ensure they have proper authorization before scanning or probing networks

. Unauthorized use of this tool may be illegal and could lead to legal consequences. **iguana** is intended strictly for educational purposes, ethical hacking, and network diagnostics.

---

## Contributing

Contributions are welcome! If you have ideas for new features or improvements, feel free to fork the repository, make changes, and submit a pull request.

### Contribution Guidelines:
- Ensure your code adheres to clean coding standards.
- Provide meaningful commit messages.
- Test your changes thoroughly before submitting a pull request.

### TODOs for Future Versions:
- Add SSL/TLS certificate analysis.
- Implement automated vulnerability assessments.
- Integrate with more external APIs for network monitoring.

---

## License

**iguana** is released under the MIT License. See the LICENSE file for more details.

---

## Requirements

- **Scapy**: For network packet manipulation and crafting.
- **dnspython**: To query DNS records and perform DNS gathering.
- **requests**: To handle API requests for Geo-IP lookups and other external data.

Install the required Python libraries:
```bash
pip install scapy dnspython requests
```

---

## Acknowledgments

A big thanks to [Kit Center](https://kitcenter.net) for their support in connecting with instructors and experts, as well as providing the infrastructure that was essential for the development of this project.

---

## Contact

For support, feedback, or inquiries, you can connect with me on:
- GitHub: [uveissmjl](https://github.com/uveissmjl)
- LinkedIn: [Uveis Smajli](https://www.linkedin.com/in/uveissmjl)

---
