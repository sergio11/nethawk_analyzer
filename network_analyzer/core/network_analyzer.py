from core.host_scanner import HostScanner
from core.port_scanner import PortScanner
from core.service_scanner import ServiceScanner
from core.smb_scanner import SMBScanner
from utils.printer import print_table

class NetworkAnalyzer:
    """
    Facade class to provide a simplified interface for network scanning operations.
    It hides the complexity of interacting with various scanners and utilities.
    """

    def __init__(self, network_range, timeout=1):
        """
        Initialize the facade with a network range and timeout.

        Args:
            network_range (str): The range of IP addresses to scan.
            timeout (int): Timeout for scanning operations (in seconds).
        """
        self.network_range = network_range
        self.timeout = timeout

        # Initialize scanners
        self.host_scanner = HostScanner(network_range, timeout)
        self.port_scanner = PortScanner(timeout)
        self.service_scanner = ServiceScanner(timeout)
        self.smb_scanner = SMBScanner(timeout)

    def scan_hosts(self, method="arp"):
        """
        Scans for active hosts on the network using the specified method.

        Args:
            method (str): Scanning method to use, e.g., "arp" for ARP scanning or "scapy" for advanced scanning.
        
        Returns:
            list: List of active hosts.
        """
        if method == "arp":
            active_hosts = self.host_scanner.scan_hosts_arp()
            print_table(active_hosts, "hosts")
            return active_hosts
        elif method == "scapy":
            active_hosts = self.host_scanner.hosts_scan()
            print_table(active_hosts, "hosts")
            return active_hosts
        else:
            raise ValueError(f"Unknown scan method: {method}")

    def scan_ports(self, hosts, port_range=(0, 10000)):
        """
        Scans open ports on a list of active hosts.

        Args:
            hosts (list): List of active hosts to scan.
            port_range (tuple): Range of ports to scan (start, end).
        
        Returns:
            dict: Dictionary of hosts and their open ports.
        """
        all_open_ports = {host: self.port_scanner.scan_ports(host, port_range) for host in hosts}
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

    def run_full_scan(self):
        """
        Runs a full scan, including host discovery, port scanning, service detection, and SMB share enumeration.

        Returns:
            dict: A dictionary containing the results of all scan stages.
        """
        print("Starting full network scan...")

        # Step 1: Scan for hosts
        print("Scanning for hosts...")
        active_hosts = self.scan_hosts(method="scapy")  # Puedes cambiar "scapy" a "arp" según necesites.

        # Step 2: Scan open ports
        print("Scanning for open ports on active hosts...")
        open_ports = self.scan_ports(active_hosts)

        # Step 3: Scan for services on open ports
        print("Scanning for services and banners...")
        services = self.scan_services(active_hosts)

        # Step 4: Scan for SMB shares
        print("Scanning for SMB shares...")
        smb_shares = self.scan_smb_shares(active_hosts)

        # Collate the results
        return {
            "hosts": active_hosts,
            "open_ports": open_ports,
            "services": services,
            "smb_shares": smb_shares
        }