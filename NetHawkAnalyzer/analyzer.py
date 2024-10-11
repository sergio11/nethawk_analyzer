import platform
import subprocess
from NetHawkAnalyzer.core.ai_security_analyzer import AISecurityAnalyzer
from NetHawkAnalyzer.core.host_scanner import HostScanner
from NetHawkAnalyzer.core.port_scanner import PortScanner
from NetHawkAnalyzer.core.service_scanner import ServiceScanner
from NetHawkAnalyzer.core.smb_scanner import SMBScanner
from NetHawkAnalyzer.utils.printer import print_table
from tqdm import tqdm


class NetHawkAnalyzer:
    """
    Facade class to provide a simplified interface for network scanning operations.
    This class abstracts the complexity of interacting with various scanners and utilities.

    Attributes:
        network_range (str): The range of IP addresses to scan.
        timeout (int): Timeout for scanning operations (in seconds).
        host_scanner (HostScanner): Instance of the host scanner.
        port_scanner (PortScanner): Instance of the port scanner.
        service_scanner (ServiceScanner): Instance of the service scanner.
        smb_scanner (SMBScanner): Instance of the SMB scanner.
    """

    def __init__(self, network_range, timeout=1, groq_api_key=None, model_id="llama3-70b-8192"):
        """
        Initializes the facade with a network range, timeout, and security analyzer.

        Args:
            network_range (str): The range of IP addresses to scan (e.g., '192.168.1.0/24').
            timeout (int): Timeout for scanning operations (in seconds). Default is 1.
            groq_api_key (str): The API key for accessing Groq services.
            model_id (str): The ID of the Groq model to use. Default is 'llama3-70b-8192'.
        """
        self.network_range = network_range
        self.timeout = timeout

        # Initialize scanners
        self.host_scanner = HostScanner(network_range, timeout)
        self.port_scanner = PortScanner(timeout)
        self.service_scanner = ServiceScanner(timeout)
        self.smb_scanner = SMBScanner(timeout)

        # Initialize the security analyzer with customizable model_id
        self.security_analyzer = AISecurityAnalyzer(model_id=model_id, groq_api_key=groq_api_key)

        self._print_banner()

    def scan_hosts(self, method="arp"):
        """
        Scans for active hosts on the network using the specified method.

        Args:
            method (str): Scanning method to use, e.g., "arp" for ARP scanning or "scapy" for advanced scanning.

        Returns:
            list: List of active hosts detected.

        Raises:
            ValueError: If an unknown scanning method is specified.
        """
        if method == "arp":
            active_hosts = self.host_scanner.scan_hosts_arp()
            print_table(active_hosts, "hosts")
            return active_hosts
        elif method == "scapy":
            active_hosts = self.host_scanner.scan_hosts_scapy()
            print_table(active_hosts, "hosts")
            return active_hosts
        else:
            raise ValueError(f"Unknown scan method: {method}")

    def scan_all_ports(self, hosts, port_range=(0, 10000)):
        """
        Scans for open ports on a list of active hosts using TCP SYN, UDP, and Xmas scans.

        Args:
            hosts (list): List of active hosts to scan.
            port_range (tuple): Range of ports to scan (start, end).

        Returns:
            dict: Dictionary of hosts and their open ports for each scan type.
        """
        all_open_ports = {host: {"TCP": [], "UDP": [], "Xmas": []} for host in hosts}

        for host in tqdm(hosts, desc="Scanning hosts for open ports"):
            # TCP SYN scan
            tcp_open_ports = self.port_scanner.scan_ports(host, port_range, scan_type='tcp')
            all_open_ports[host]["TCP"].extend(tcp_open_ports)

            # UDP scan
            udp_open_ports = self.port_scanner.scan_ports(host, port_range, scan_type='udp')
            all_open_ports[host]["UDP"].extend(udp_open_ports)

            # Xmas scan
            xmas_open_ports = self.port_scanner.scan_ports(host, port_range, scan_type='xmas')
            all_open_ports[host]["Xmas"].extend(xmas_open_ports)

        print_table(all_open_ports, "ports")
        return all_open_ports

    def scan_ports(self, hosts, scan_type='tcp', port_range=(0, 10000)):
        """
        Scans for open ports on a list of active hosts.

        Args:
            hosts (list): List of active hosts to scan.
            port_range (tuple): Range of ports to scan (start, end).

        Returns:
            dict: Dictionary of hosts and their open ports.
        """
        all_open_ports = {host: self.port_scanner.scan_ports(host, scan_type, port_range) for host in hosts}
        print_table(all_open_ports, "ports")
        return all_open_ports

    def scan_services(self, hosts, port_range=(0, 10000)):
        """
        Scans for services and retrieves banners from open ports on hosts.

        Args:
            hosts (list): List of active hosts to scan.
            port_range (tuple): Range of ports to scan for services (start, end).

        Returns:
            dict: Dictionary of hosts and their detected services.
        """
        services_info = {host: self.service_scanner.scan_services(host, port_range) for host in hosts}
        print_table(services_info, "services")
        return services_info
    
    def scan_smb_shares(self, hosts):
        """
        Scans for public SMB shares on a list of active hosts.

        Args:
            hosts (list): List of active hosts to scan for SMB shares.

        Returns:
            dict: Dictionary of hosts and their discovered SMB shares.
        """
        smb_shares = self.smb_scanner.scan_smb_shares(hosts)
        print_table(smb_shares, "shares")
        return smb_shares

    def run_full_scan(self, pdf_path="nethawk_security_report.pdf", json_path="nethawk_security_report.json"):
        """
        🛡️ Runs a full scan, including host discovery, port scanning, service detection, and SMB share enumeration.

        Returns:
            dict: A dictionary containing the results of all scan stages.
        """
        print("🚀 Starting full network scan...")

        # Step 1: Check network connectivity
        if not self._check_connectivity():
            print("❌ Network connectivity could not be verified. Aborting scan.")
            return

        # Step 2: Scan for hosts
        print("🌐 Scanning for hosts...")
        active_hosts = self.scan_hosts(method="scapy")

        # Step 3: Scan open ports
        print("🔍 Scanning for open ports on active hosts...")
        open_ports = self.scan_ports(active_hosts)

        # Step 4: Scan for services on open ports
        print("🛠️ Scanning for services and banners...")
        services = self.scan_services(active_hosts)

        # Step 5: Scan for SMB shares
        print("📁 Scanning for SMB shares...")
        smb_shares = self.scan_smb_shares(active_hosts)

        # Prepare the results for analysis
        scan_results = {
            "hosts": active_hosts,         # 🌐 Active hosts discovered
            "open_ports": open_ports,      # 🚪 Open ports found
            "services": services,          # 🛠️ Services and banners
            "smb_shares": smb_shares       # 📁 SMB shares discovered
        }

        # Step 6: Generate a security analysis report
        print("📝 Generating security analysis report...")
        report = self.security_analyzer.analyze_scan_results(scan_results, pdf_path=pdf_path, json_path=json_path)

        # Print the generated report
        if report:
            print("🔍 Security analysis report generated successfully.")
        else:
            print("❌ Failed to generate security analysis report.")

        return scan_results 
    
    def _check_connectivity(self):
        """
        Checks the network connectivity by examining the default route and network interfaces.
        
        Returns:
            bool: True if a valid route and network interface is found, False otherwise.
        """
        system_platform = platform.system()

        try:
            if system_platform == "Linux" or system_platform == "Darwin":  # For Linux/macOS
                print("Checking connectivity on Linux/macOS...")
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                if 'default' in result.stdout:
                    print("Default route found. Network connectivity looks good.")
                    return True
                else:
                    print("No default route found. Check your network settings.")
                    return False

            elif system_platform == "Windows":  # For Windows
                print("Checking connectivity on Windows...")
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
                if '0.0.0.0' in result.stdout:
                    print("Default route found. Network connectivity looks good.")
                    return True
                else:
                    print("No default route found. Check your network settings.")
                    return False

            else:
                print(f"Unsupported platform: {system_platform}")
                return False

        except Exception as e:
            print(f"Error while checking connectivity: {str(e)}")
            return False

    def _print_banner(self):
        """
        Prints a welcome banner at the start of the program.
        """
        banner = """
        ███╗   ██╗███████╗████████╗██╗  ██╗ █████╗ ██╗    ██╗ ██╗  ██╗
        ████╗  ██║██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║    ██║ ██║ ██╔╝
        ██╔██╗ ██║█████╗     ██║   ███████║███████║██║ █╗ ██║ █████╔╝ 
        ██║╚██╗██║██╔══╝     ██║   ██╔══██║██╔══██║██║███╗██║ ██╔═██╗ 
        ██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║╚███╔███╔╝ ██║  ██╗
        ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═╝  ╚═╝
        """
        print(banner)