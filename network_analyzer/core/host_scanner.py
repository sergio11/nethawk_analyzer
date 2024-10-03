import logging
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from scapy.all import *
import socket
from tqdm import tqdm

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class HostScanner:
    """
    A class for scanning hosts on a given network range using various techniques.
    
    The class implements a multi-tiered scanning strategy to detect active hosts:
    
    1. **ICMP Ping**: Sends an ICMP Echo Request to check if the host is alive.
    2. **TCP SYN Scan**: Sends SYN packets to specified ports to check for open ports.
    3. **TCP ACK Scan**: If SYN scans fail, sends ACK packets to verify the host's responsiveness.
    4. **Fallback to Socket Scan**: If both SYN and ACK scans fail, attempts a TCP connection using the socket library to identify open ports.

    The intention is to maximize host detection even when certain packets may be blocked by firewalls or other network security measures.
    """

    def __init__(self, network_range, timeout=1):
        """Initialize the host scanner with a network range and timeout.
        
        Args:
            network_range (str): The range of IP addresses to scan.
            timeout (int): Timeout for scanning operations (in seconds).
        """
        self.network_range = network_range
        self.timeout = timeout

        # Setup logging to provide detailed output
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def _send_ping(self, ip):
        """Send an ICMP Echo Request (Ping) to detect if a host is alive.
        
        Args:
            ip (str): IP address of the host to ping.

        Returns:
            tuple: (ip, status) where status is True if the host is reachable.
        """
        icmp_request = IP(dst=ip) / ICMP()
        answered, _ = sr(icmp_request, timeout=self.timeout, verbose=0)
        if answered:
            return (ip, True)
        return (ip, False)

    def _scan_host_scapy(self, ip, scan_ports=(80, 443, 22, 135, 445, 139)):
        """Uses Scapy to send a TCP SYN packet, followed by TCP ACK if needed, and falls back to socket scan.
        
        Args:
            ip (str): IP address of the host to scan.
            scan_ports (tuple): Ports to scan.

        Returns:
            tuple: (ip, status) where status is True if at least one port is open.
        """
        logging.debug(f"Scanning host {ip} on ports {scan_ports}")

        # Step 1: Try to ping the host using ICMP
        ip_status = self._send_ping(ip)
        if ip_status[1]:
            logging.info(f"Host {ip} is up (ICMP Ping)")
            return ip_status

        # Step 2: Try TCP SYN scan
        for port in scan_ports:
            syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')  # SYN packet
            answered, _ = sr(syn_packet, timeout=self.timeout, verbose=0)

            if answered:
                for snd, rcv in answered:
                    # Check if we get SYN-ACK (port open) or RST (port closed)
                    if rcv.haslayer(TCP) and rcv[TCP].flags == 'SA':  # SYN-ACK response
                        logging.info(f"Host {ip} has an open port (SYN): {port}")
                        return (ip, True)

        # Step 3: If SYN scan fails, try TCP ACK scan
        for port in scan_ports:
            ack_packet = IP(dst=ip) / TCP(dport=port, flags='A')  # ACK packet
            answered, _ = sr(ack_packet, timeout=self.timeout, verbose=0)

            if answered:
                for snd, rcv in answered:
                    # If there's any response, assume the host is up
                    if rcv.haslayer(TCP):
                        logging.info(f"Host {ip} responded to ACK on port: {port}")
                        return (ip, True)

        # Step 4: Fallback to socket scan if SYN and ACK fail
        logging.info(f"SYN and ACK scans failed for {ip}. Falling back to socket connection.")
        return self._scan_host_socket(ip, scan_ports)

    def _scan_host_socket(self, ip, scan_ports):
        """Uses socket connection to check if a host has any open ports.
        
        Args:
            ip (str): IP address of the host to scan.
            scan_ports (tuple): Ports to scan.

        Returns:
            tuple: (ip, status) where status is True if at least one port is open.
        """
        for port in scan_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    logging.info(f"Host {ip} is up (Socket connection on port {port})")
                    return (ip, True)
            except (socket.timeout, socket.error):
                pass  # Continue to the next port if this one fails

        return (ip, False)

    def scan_hosts_scapy(self, scan_ports=(80, 443, 22, 135, 445, 139)):
        """Performs a host scan using Scapy with a combination of SYN, ACK, and socket scans.

        Args:
            scan_ports (tuple): Ports to use for detecting host activity.

        Returns:
            list: List of active host IP addresses.
        """
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        total_hosts = sum(1 for _ in network.hosts())  # Total number of hosts
        active_hosts_count = 0

        logging.info(f"Starting Scapy scan for {total_hosts} hosts in network: {self.network_range}")
        logging.info(f"Ports being scanned: {scan_ports}")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc="Scanning hosts")}

            for future in tqdm(futures, desc="Getting results", leave=False):
                try:
                    result = future.result()
                    ip_address = futures[future]

                    if result[1]:  # Host is up
                        hosts_up.append(result[0])
                        active_hosts_count += 1
                        logging.info(f"Host UP: {result[0]} (Active hosts so far: {active_hosts_count})")
                    else:
                        logging.debug(f"Host DOWN: {ip_address}")

                except Exception as e:
                    logging.error(f"Error scanning host {futures[future]}: {e}")

        logging.info(f"Scapy host scan completed. {active_hosts_count} hosts are active out of {total_hosts} scanned.")
        return hosts_up