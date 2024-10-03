from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from scapy.all import IP, TCP, sr

class PortScanner:
    def __init__(self, timeout=1):
        """Initialize the port scanner with a timeout."""
        self.timeout = timeout

    def _scan_port_scapy(self, ip, port):
        """Uses Scapy to send a SYN packet to a specified port and checks for responses."""
        packet = IP(dst=ip) / TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
        answered, _ = sr(packet, timeout=self.timeout, verbose=0)
        return port, bool(answered)

    def scan_ports(self, ip, port_range=(0, 10000)):
        """Scans ports on a given host using Scapy."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in tqdm(range(*port_range), desc=f"Scanning ports on {ip}"):
                futures.append(executor.submit(self._scan_port_scapy, ip, port))
            for future in futures:
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
        return open_ports