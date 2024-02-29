## Iguana: A Network Analysis Suite

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


Iguana is an open-source, Python-based tool designed for network enthusiasts, cybersecurity students, and professionals looking to perform comprehensive network analyses. It integrates a variety of functionalities into one convenient suite, enabling users to inspect and audit networks efficiently. With Iguana, you can perform network scanning to discover active devices, conduct port scanning to identify open ports, capture and analyze network traffic, and gather DNS information for domain reconnaissance.

This tool is developed with the intention of providing a practical resource for learning about network security and diagnostics. Whether you're troubleshooting a network, auditing the security of a system, or just learning about network protocols and interactions, Iguana offers a user-friendly approach without compromising on depth and utility.

## Features include:

    Network Scanning: Quickly identify active devices within a network.
    Port Scanning: Examine devices to find exposed services and potential vulnerabilities.
    Network Sniffing: Analyze traffic for troubleshooting and educational purposes.
    DNS Gathering: Collect detailed DNS information to aid in network reconnaissance.

Iguana is created with the ethos of ethical usage and educational purpose in mind. It's perfect for those who are new to network security or experienced professionals looking for a lightweight, scriptable solution. The tool is continually evolving, and contributions are welcome to extend its functionality and improve user experience.

Note: Iguana is intended for legal and ethical use only. Users must ensure they have proper authorization before scanning or probing networks. Unauthorized use of this tool is strictly prohibited and may lead to legal consequences.

For installation instructions, usage details, and contributing guidelines, please refer to the respective sections of this repository.

Happy Scanning!




## Getting started!

```markdown
# Iguana

Iguana is an open-source, Python-based network analysis suite designed for cybersecurity enthusiasts, network administrators, and educational purposes. This tool integrates functionalities for network scanning, port scanning, packet sniffing, and DNS information gathering, offering a streamlined approach to network diagnostics and security auditing.

## Features

- **Network Scanning**: Discover active devices within a specified IP range.
- **Port Scanning**: Identify open ports on devices and assess network security.
- **Network Sniffing**: Capture and analyze network traffic.
- **DNS Gathering**: Retrieve DNS records associated with a domain.
```
## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/uveissmjl/Iguana.git
   ```
2. Navigate to the cloned directory:
   ```bash
   cd Iguana
   ```
3. Install the required Python libraries:
   ```bash
   pip install scapy dnspython
   ```
4. Make the script executable (optional):
   ```bash
   chmod +x iguana.py
   ```

## Usage

Below are examples of how to use each feature of Iguana:

- **Network Scanning**:
  ```bash
  ./iguana.py -m scan --ip 192.168.1.0/24
  ```
- **Port Scanning**:
  ```bash
  ./iguana.py -m port-scan --ip 192.168.1.1
  ```
- **Network Sniffing**:
  ```bash
  sudo ./iguana.py -m sniff --interface eth0
  ```
- **DNS Gathering**:
  ```bash
  ./iguana.py -m dns-gather --domain example.com
  ```

Replace parameters like `192.168.1.0/24`, `192.168.1.1`, `eth0`, and `example.com` with your target information.

## Legal Disclaimer

This tool is intended for legal and ethical use only. Unauthorized scanning and probing of networks may be illegal and unethical. Users are responsible for their actions and should ensure they have permission before engaging in any network scanning activities.

## Contributing

Contributions are welcome! If you have improvements or new features, feel free to fork the repository, make changes, and submit a pull request. Please ensure your code adheres to clean coding standards for easy integration.

## License

Iguana is released under the MIT License. See the LICENSE file for more details.

## Acknowledgments

- Thanks to the developers of Scapy and dnspython for providing the libraries that make Iguana possible.

## Contact

For support, feedback, or questions, connect with me on [GitHub](https://github.com/uveissmjl) or [LinkedIn](https://www.linkedin.com/in/uveissmjl).
