from concurrent.futures import ThreadPoolExecutor
import ipaddress
from scapy.all import ARP, Ether, srp, IP, TCP
from tqdm import tqdm

class HostScanner:
    def __init__(self, network_range, timeout=1):
        """Initialize the host scanner with a network range and timeout."""
        self.network_range = network_range
        self.timeout = timeout

    def scan_hosts_arp(self):
        """Performs ARP scan to identify active hosts on the network."""
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        
        # Send the ARP request and capture the responses
        answered, _ = srp(arp_request, timeout=self.timeout, verbose=0)
        
        for _, received in answered:
            hosts_up.append(received.psrc)
        return hosts_up

    def _scan_host_scapy(self, ip, scan_ports=(135, 445, 139)):
        """Uses Scapy to send a TCP SYN packet to multiple ports and detects responses.

        Args:
            ip (str): IP address of the host to scan.
            scan_ports (tuple): Ports to scan.

        Returns:
            tuple: (ip, status) where status is True if at least one port is open.
        """
        for port in scan_ports:
            packet = IP(dst=ip) / TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            answered, _ = sr(packet, timeout=self.timeout, verbose=0)
            if answered:
                return (ip, True)
        return (ip, False)

    def scan_hosts_scapy(self, scan_ports=(135, 445, 139)):
        """Performs a host scan using advanced Scapy techniques.

        Args:
            scan_ports (tuple): Ports to use for detecting host activity.

        Returns:
            list: List of active host IP addresses.
        """
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(), desc="Scanning hosts")}
            for future in tqdm(futures, desc="Getting results"):
                if future.result()[1]:  # Check if the host is up
                    hosts_up.append(future.result()[0])
        return hosts_up