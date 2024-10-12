import argparse
import sys
from scapy.all import ARP, Ether, srp, sniff
import socket
import dns.resolver
import threading
import requests


iguana_art = """
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
"""

# Function to display help message
def help_message():
    print("""
Usage:
╭────────────────────────────────────────────────────────────────────────────────────╮
│                              Iguana Tool Usage                                     │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Usage:                                                                             │
│   python iguana.py -m scan --ip [IP range]           : Scan specified IP range.    │
│   python iguana.py -m port-scan --ip [IP address]    : Scan open ports on IP.      │
│   python iguana.py -m sniff --interface [Interface]  : Sniff packets on interface. │
│   python iguana.py -m dns-gather --domain [Domain]   : Gather DNS info for domain. │
│   python iguana.py -m geo-ip --ip [IP address]       : Find Geo-location of IP.    │
│   python iguana.py -m vuln-check --ip [IP address]   : Check for common open ports │
│                                                      and possible vulnerabilities. │
│   python iguana.py -m my-ip                          : Find your public IP address │
│                                                      and optionally get its        │
│                                                      location.                     │
│   python iguana.py -h or --help                      : Show help message and exit. │
╰────────────────────────────────────────────────────────────────────────────────────╯
""")


# Function to perform a basic network scan
def scan_network(ip):
    print(f"Scanning network: {ip}")
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, unanswered = srp(packet, timeout=2, verbose=False)
    result_data = "IP Address\t\tMAC Address\n-----------------------------------------\n"
    for sent, received in answered:
        line = f"{received.psrc}\t\t{received.hwsrc}"
        print(line)
        result_data += line + "\n"
    
    return result_data

        
# Function to perform a basic port check
def check_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # Returns True if the port is open
    except Exception as e:
        print(f"Error checking port {port} on {ip}: {e}")
        return False
#Function for Port-Scan
def port_scan(ip, start_port=1, end_port=1024, num_threads=100):
    print(f"Scanning ports on: {ip}")
    result_data = f"Port scan results for {ip}:\n"
    open_ports = []

    def thread_function(port):
        if check_port(ip, port):
            port_info = f"Port {port} is open."
            print(port_info)
            open_ports.append(port_info)

    threads = []

    # Create threads for each port
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=thread_function, args=(port,))
        threads.append(thread)
        thread.start()

        # Join threads in batches to control the number of concurrent threads
        if len(threads) == num_threads:
            for thread in threads:
                thread.join()
            threads = []

    # Wait for all remaining threads to complete
    for thread in threads:
        thread.join()

    # Combine the results into a single string
    result_data += "\n".join(open_ports) + "\n"
    return result_data


# Function to sniff network packets
def network_sniff(interface, packet_count=10):
    print(f"Sniffing on interface: {interface}")
    packets = sniff(iface=interface, count=packet_count)
    result_data = f"Sniffed {packet_count} packets on interface {interface}:\n"
    for packet in packets:
        packet_summary = packet.summary()
        print(packet_summary)
        result_data += packet_summary + "\n"
    return result_data


#Function for DNS Gathering 
def dns_gather(domain):
    print(f"Gathering DNS information for: {domain}")
    result_data = f"DNS Information for {domain}:\n"
    records = ['A', 'MX', 'NS', 'TXT']
    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            result_data += f"\n{record} Records:\n"
            for answer in answers:
                print(answer)
                result_data += f"{answer}\n"
        except Exception as e:
            error_message = f"Could not gather {record} record: {e}"
            print(error_message)
            result_data += error_message + "\n"
    return result_data


#Function for Public-IP Address
def get_public_ip():
    try:
        response = requests.get('https://api64.ipify.org?format=json')
        data = response.json()
        public_ip = data.get('ip')
        return public_ip
    except requests.RequestException as e:
        error_message = f"Could not retrieve public IP: {e}"
        print(error_message)
        return error_message

#Function for Geo-IP Lookup
def geo_ip_lookup(ip):
    try:
        # Make a request to ipinfo.io for the given IP
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()  
        data = response.json()

        # Construct the result string with the IP information
        result_data = f"Geo-IP Information for {ip}:\n"
        result_data += f"IP: {data.get('ip', 'N/A')}\n"
        result_data += f"City: {data.get('city', 'N/A')}\n"
        result_data += f"Region: {data.get('region', 'N/A')}\n"
        result_data += f"Country: {data.get('country', 'N/A')}\n"
        result_data += f"Location: {data.get('loc', 'N/A')}\n"
        result_data += f"Organization: {data.get('org', 'N/A')}\n"
        result_data += f"Postal: {data.get('postal', 'N/A')}\n"
        print(result_data)  # Display the information
        return result_data
    except requests.RequestException as e:
        error_message = f"Could not perform Geo-IP lookup for {ip}: {e}"
        print(error_message)
        return error_message


#Function for Vulnerability Check
def vulnerability_check(ip):
    print(f"Checking for common vulnerabilities on: {ip}")
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP"
    }
    result_data = f"Vulnerability check for {ip}:\n"
    for port, service in common_ports.items():
        if check_port(ip, port):
            warning = f"Warning: {service} (Port {port}) is open and may be vulnerable."
            print(warning)
            result_data += warning + "\n"
        else:
            status = f"{service} (Port {port}) is closed."
            print(status)
            result_data += status + "\n"
    return result_data

#Function for Save-Option
def save_results_to_file(data):
    if data and isinstance(data, str):  
        choice = input("Would you like to save the results to a text file? (y/n): ").lower()
        if choice == 'y':
            file_name = input("Enter the file name (e.g., results.txt): ")
            signature = "\n\nResults saved from Iguana, developed by uveissmjl."
            with open(file_name, 'w') as file:
                file.write(data + signature)
            print(f"Results saved to {file_name}")
        else:
            print("Results not saved.")
    else:
        print("No valid data to save.")

def main():
    # Print iguana art in bright green
    print(f"\033[92m{iguana_art}\033[0m")

    parser = argparse.ArgumentParser(description='Iguana Network Tools', add_help=False)  # Disable automatic help
    parser.add_argument('-m', '--mode', help='Mode of operation: scan, port-scan, sniff, dns-gather')
    parser.add_argument('--ip', help='IP address or range for scanning')
    parser.add_argument('--interface', help='Network interface for sniffing')
    parser.add_argument('--domain', help='Domain for DNS gathering')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit.')  
    args = parser.parse_args()

    if args.help:
        help_message()
        sys.exit(0)

    # Mode operations
    if args.mode == 'scan':
        if args.ip:
            result_data = scan_network(args.ip)
            save_results_to_file(result_data)
        else:
            print("IP range is required for network scanning.")
            sys.exit(1)

    elif args.mode == 'port-scan':
        if args.ip:
            result_data = port_scan(args.ip)
            save_results_to_file(result_data)
        else:
            print("IP address is required for port scanning.")
            sys.exit(1)

    elif args.mode == 'sniff':
        if args.interface:
            result_data = network_sniff(args.interface)
            save_results_to_file(result_data)
        else:
            print("Network interface is required for sniffing.")
            sys.exit(1)

    elif args.mode == 'dns-gather':
        if args.domain:
            result_data = dns_gather(args.domain)
            save_results_to_file(result_data)
        else:
            print("Domain name is required for DNS gathering.")
            sys.exit(1)

    elif args.mode == 'geo-ip':
        if args.ip:
            result_data = geo_ip_lookup(args.ip)
            save_results_to_file(result_data)
        else:
            print("IP address is required for Geo-IP lookup.")
            sys.exit(1)

    elif args.mode == 'vuln-check':
        if args.ip:
            result_data = vulnerability_check(args.ip)
            save_results_to_file(result_data)
        else:
            print("IP address is required for vulnerability checking.")
            sys.exit(1)

    if args.mode == 'my-ip':
        public_ip = get_public_ip()
        if public_ip:
            print(f"Your public IP address is: {public_ip}")
            choice = input("Would you like to find the location of this IP? (y/n): ").lower()
            if choice == 'y':
                result_data = geo_ip_lookup(public_ip)
                save_results_to_file(result_data)
            else:
                save_results_to_file(f"Your public IP address is: {public_ip}\n")

 
    else:
        print("Invalid or unimplemented mode. Use -h or --help for more information.")

if __name__ == "__main__":
    main()
