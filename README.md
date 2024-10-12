# NetHawk 🦅: AI-Powered Ethical Hacking & Network Vulnerability Assessment 🔍💻🛡️🌐

NetHawk is an advanced, AI-powered tool designed for ethical hacking and comprehensive network vulnerability assessment. Built for cybersecurity professionals, network administrators, and ethical hackers, NetHawk utilizes powerful tools like Scapy and Nmap to perform deep scans, analyze network security, and uncover potential vulnerabilities in target systems.

Thanks to AI-driven automation and intelligent decision-making, NetHawk simplifies port scanning, vulnerability detection, and report generation, making security audits faster, smarter, and more efficient.

## 🌟 Key Features:

- 🔧 **Multi-Tool Scanning**: Combines the power of Scapy and Nmap to conduct in-depth network scans, ensuring a comprehensive view of network activity and vulnerabilities.
  
- 🚪 **Aggressive and Comprehensive Port Scanning**: Supports TCP, UDP, and Xmas scans to detect open, closed, and filtered ports, identifying potential entry points for attackers.

- 📊 **Result Consolidation**: Merges scan results from both tools to eliminate duplicates, providing a clear and consolidated view of your network's security status.

- ⚡ **High Concurrency**: Efficiently scans wide ranges of ports using multiple threads, allowing for fast and scalable performance for networks of any size.

- ⏱️ **Customizable Settings**: Configure parameters and timeouts according to your network conditions and security requirements.

- 🤖 **AI-Powered Analysis**: Offers smarter vulnerability analysis with actionable insights, helping you take appropriate measures based on findings.

## 🎯 Use Cases:

- 🔓 **Penetration Testing**: Ethical hackers can quickly identify exploitable vulnerabilities in networks, strengthening defenses before malicious actors can attack.

- 🔍 **Network Security Auditing**: IT teams can use NetHawk to audit network security, scanning for open ports, misconfigured services, and hidden vulnerabilities.

## 🔍 Host and Port Scanning Strategy:

NetHawk employs an efficient combination of Scapy and Nmap to perform host and port scanning, providing comprehensive and redundant coverage, ensuring maximum detection of active hosts and open ports, even in networks with firewall defenses.

### 1. **Host Detection with Scapy**:

- **ICMP Ping**: First, NetHawk uses ICMP packets (ping) sent to each host within the target network range to check their availability. If a host responds, it is considered "active."

- **TCP SYN and ACK Scanning**: For hosts that do not respond to the ping, NetHawk performs a TCP SYN scan, sending SYN packets to the most common ports (80, 443, 22, etc.) to identify responses indicating open ports. If no response is received for the SYN, an ACK scan is attempted to determine if the host is responding to TCP packets.

- **Fallback to Socket Scan**: If the previous scans fail (possibly due to firewalls blocking ICMP or SYN packets), a direct connection attempt is made using sockets on the same ports, looking for any response that may indicate an open port.

### 2. **Port Scanning with Scapy and Nmap**:

- **Scapy**: For hosts identified as active, NetHawk uses Scapy to perform deep port scans. Various scan types are supported, including:
  - **TCP SYN**: Sending SYN packets to discover open ports.
  - **UDP Scan**: Using UDP packets to detect open or filtered ports.
  - **Xmas Scan**: Scanning with malformed TCP packets to test for anomalous responses that may indicate filtered or closed ports.

- **Nmap**: NetHawk complements Scapy's results with an Nmap scan, providing additional detection capabilities such as identifying service versions and checking less common ports. Nmap is run by default to scan the most commonly used ports or can be configured for custom scans based on specific security requirements.

- The results from Nmap are consolidated with those from Scapy, eliminating duplicates to offer a clear and detailed final report.

### 3. **Aggregation and Analysis of Results**:

NetHawk combines the results from both scans (Scapy and Nmap) to generate a complete list of active hosts and open ports. By merging results from different approaches, duplication is eliminated, providing a unique view of potential network vulnerabilities. With this combination of techniques, NetHawk ensures complete coverage, detecting hosts and open ports that may be hidden from more conventional scanning methods.

## 🌐 Using the NetHawk API

NetHawk provides a powerful and simplified API for conducting security analyses and network scans. This API abstracts the complexity of using tools like Scapy and Nmap, allowing users to interact with various scanning and vulnerability analysis functions efficiently. Below is a guide to its main methods and functionalities:

#### 1. 🚀 **Initialization (`__init__`)**

The main object of the API is the `NetHawkAnalyzer` class. To get started, you need to provide a network range (`network_range`) and other optional parameters like timeout (`timeout`) and an AI API key if necessary.

- **`network_range`**: The range of IP addresses to scan (e.g., `192.168.1.0/24`).
- **`timeout`**: Timeout in seconds.
- **`groq_api_key`** and **`model_id`**: Optional keys for integration with AI services.

#### 2. 🔍 **Host Scanning (`scan_hosts`)**

This method detects active devices on the network, supporting the following scanning methods:

- **`arp`**: Fast, based on ARP, but limited to local networks.
- **`scapy`**: More advanced scanning that can detect hosts through firewalls.

The result is a list of active hosts ready for the next step.

#### 3. 🚪 **Port Scanning (`scan_ports` and `scan_all_ports`)**

NetHawk scans ports using various techniques to detect open ports:

- **TCP SYN**: Detects open TCP ports.
- **UDP Scan**: Scans for open or filtered UDP ports.
- **Xmas Scan**: Uses malformed packets to identify filtered ports.

The **`scan_all_ports`** method runs all scan types simultaneously to provide a comprehensive view of open ports on each host.

#### 4. 🛠️ **Service Detection (`scan_services`)**

NetHawk allows the identification of services running on open ports and retrieves banner information:

- **`scan_services`**: Scans a list of hosts to detect services and versions, which is crucial for identifying potential vulnerabilities.

#### 5. 📁 **SMB Share Scanning (`scan_smb_shares`)**

You can also scan hosts for public SMB shares:

- **`scan_smb_shares`**: Detects shared resources via SMB, helping identify unauthorized access points in the network.

#### 6. 📝 **Full Network Scan (`run_full_scan`)**

For a comprehensive analysis, use the **`run_full_scan`** method, which combines all scanning functionalities into a single operation:

- This method performs host discovery, port scanning, service detection, and SMB share enumeration.
- Results can be output in both PDF and JSON formats for detailed reporting and analysis.

### ⚠️ **Error Handling**

The API raises specific errors for known issues, such as:

- **`ValueError`**: Raised for unknown scanning methods.
- Proper error handling ensures users are informed of any issues during the scanning process.

## 📦 Required Dependencies

| Dependency              | Version    | Description                                                                                   |
|-------------------------|------------|-----------------------------------------------------------------------------------------------|
| **scapy**               | `2.6.0`   | A powerful Python library used for network packet manipulation and analysis.                 |
| **tqdm**                | `4.65.0`   | A fast, extensible progress bar for loops and file processing.                               |
| **rich**                | `13.9.2`  | A library for rich text and beautiful formatting in the terminal.                             |
| **pysmb**               | `1.2.10`  | A Python implementation of the SMB/CIFS protocol for network file sharing.                    |
| **python3-nmap**       | `1.9.1`   | A Python library that allows you to interact with Nmap from your Python scripts.            |
| **langchain**           | `0.2.16`  | A framework for building applications with language models and AI capabilities.               |
| **langchain-groq**      | `0.1.10`  | An extension for Langchain that enables integration with Groq-based systems.                  |
| **fpdf2**               | `2.8.1`   | A library for generating PDF documents using Python.                                         |
| **python-dotenv**       | `1.0.1`   | A tool to read key-value pairs from a `.env` file and set them as environment variables.     |



