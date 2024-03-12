import argparse
import sys
from scapy.all import ARP, Ether, srp, sniff
import socket
import dns.resolver
import threading

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
│   python iguana.py -m scan --ip [IP range] : Scan specified IP range.              │
│   python iguana.py -m port-scan --ip [IP address] : Scan open ports on IP.         │
│   python iguana.py -m sniff --interface [Interface] : Sniff packets on interface.  │
│   python iguana.py -m dns-gather --domain [Domain] : Gather DNS info for domain.   │
│   python iguana.py -h or --help             : Show help message and exit.          │
╰────────────────────────────────────────────────────────────────────────────────────╯
""")


# Function to perform a basic network scan
def scan_network(ip):
    print(f"Scanning network: {ip}")
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, unanswered = srp(packet, timeout=2, verbose=False)
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for sent, received in answered:
        print(f"{received.psrc}\t\t{received.hwsrc}")
        
# Function to perform a basic port scan
def check_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(timeout)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port}: Open")
    sock.close()

def port_scan(ip, start_port=1, end_port=1024, num_threads=100):
    print(f"Scanning ports on: {ip}")
    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=check_port, args=(ip, port))
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


# Function to sniff network packets
def network_sniff(interface, packet_count=10):
    print(f"Sniffing on interface: {interface}")
    packets = sniff(iface=interface, count=packet_count)
    for packet in packets:
        print(packet.summary())

#Function for DNS Gathering 
def dns_gather(domain):
    print(f"Gathering DNS information for: {domain}")
    records = ['A', 'MX', 'NS', 'TXT']
    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"\n{record} Records:")
            for answer in answers:
                print(answer)
        except Exception as e:
            print(f"Could not gather {record} record: {e}")

def main():
    # Print iguana art in bright green
    print(f"\033[92m{iguana_art}\033[0m")

    parser = argparse.ArgumentParser(description='Iguana Network Tools', add_help=False)  # Disable automatic help
    parser.add_argument('-m', '--mode', help='Mode of operation: scan, port-scan, sniff, dns-gather')
    parser.add_argument('--ip', help='IP address or range for scanning')
    parser.add_argument('--interface', help='Network interface for sniffing')
    parser.add_argument('--domain', help='Domain for DNS gathering')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit.')  # Custom help option
    args = parser.parse_args()

    if args.help:
        help_message()
        sys.exit(0)

    # Mode operations
    if args.mode == 'scan':
        if args.ip:
            scan_network(args.ip)
        else:
            print("IP range is required for network scanning.")
            sys.exit(1)

    elif args.mode == 'port-scan':
        if args.ip:
            port_scan(args.ip)
        else:
            print("IP address is required for port scanning.")
            sys.exit(1)

    elif args.mode == 'sniff':
        if args.interface:
            network_sniff(args.interface)
        else:
            print("Network interface is required for sniffing.")
            sys.exit(1)

    elif args.mode == 'dns-gather':
        if args.domain:
            dns_gather(args.domain)
        else:
            print("Domain name is required for DNS gathering.")
            sys.exit(1)

    else:
        print("Invalid or unimplemented mode. Use -h or --help for more information.")

if __name__ == "__main__":
    main()
