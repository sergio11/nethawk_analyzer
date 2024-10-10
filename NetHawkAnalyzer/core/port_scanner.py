import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, RandShort
import nmap3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class PortScanner:
    """
    A class to scan ports using Scapy and Nmap.
    
    This class provides methods to perform TCP, UDP, and Xmas scans on a specified host. 
    It can also utilize Nmap for additional scanning capabilities, and it aggregates results 
    from both Scapy and Nmap to provide a comprehensive view of open ports.
    
    Attributes:
        timeout (int): The timeout for each packet sent during the scan.
    """

    def __init__(self, timeout=2):
        """Initialize the port scanner with a timeout."""
        self.timeout = timeout

    def _nmap_scan(self, ip, args=None):
        """Scans ports using nmap3."""
        nmap = nmap3.Nmap()
        logger.info(f"🔍 Performing Nmap scan on {ip}...")
        try:
            if args is None:
                results = nmap.scan_top_ports(ip)
            else:
                results = nmap.scan(ip, args)
            logger.info(f"✅ Nmap scan completed on {ip}")
            return results
        except Exception as e:
            logger.error(f"⚠️ Error during Nmap scan on {ip}: {e}")
            return None

    def _scan_port_scapy(self, ip, port):
        """Uses Scapy to send a SYN packet to a specified port and checks for responses."""
        conf.verb = 0  # Set to 1 to enable verbosity for debugging
        sport = RandShort()  # Generate a random source port

        # Send TCP SYN packet
        packet = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S')
        response = sr1(packet, timeout=self.timeout)

        # Check if we got a response
        if response:
            # Check if it's a SYN-ACK (port is open)
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                # Send RST to close the connection (polite way)
                sr1(IP(dst=ip) / TCP(dport=port, flags='R'), timeout=self.timeout)
                logger.info(f"🔓 Port {port} is open on {ip}.")
                return port, "Open"
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                logger.debug(f"🚫 Port {port} is closed on {ip}.")
                return port, "Closed"
        logger.debug(f"🔒 Port {port} is filtered on {ip}.")
        return port, "Filtered"

    def _udp_scan(self, ip, port):
        """Uses Scapy to send a UDP packet to a specified port and checks for responses."""
        sport = RandShort()  # Generate a random source port
        packet = IP(dst=ip) / UDP(sport=sport, dport=port)
        response = sr1(packet, timeout=self.timeout)

        # Check if we got a response
        if response is None:
            logger.info(f"🔓 Port {port} is open or filtered on {ip}.")
            return port, "Open / filtered"  # No response means open/filtered
        elif response.haslayer(ICMP):
            logger.debug(f"🚫 Port {port} is closed on {ip}.")
            return port, "Closed"  # Closed if we got an ICMP response
        logger.debug(f"❓ Port {port} returned an unknown response on {ip}.")
        return port, "Unknown response"

    def _xmas_scan(self, ip, port):
        """Uses Scapy to send a TCP Xmas packet to a specified port and checks for responses."""
        sport = RandShort()  # Generate a random source port
        packet = IP(dst=ip) / TCP(sport=sport, dport=port, flags='FPU')
        response = sr1(packet, timeout=self.timeout)

        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                logger.debug(f"🚫 Port {port} is closed on {ip}.")
                return port, "Closed"
            elif response.haslayer(ICMP):
                logger.debug(f"🔒 Port {port} is filtered on {ip}.")
                return port, "ICMP response / filtered"
        logger.info(f"🔓 Port {port} is open or filtered on {ip}.")
        return port, "Open / filtered"

    def scan_ports(self, ip, scan_type='tcp', port_range=(0, 65535)):
        """
        Scans ports on a given host using Scapy and Nmap.

        Args:
            ip (str): The IP address of the host to scan.
            scan_type (str): The type of scan to perform ('tcp', 'udp', 'xmas').
            port_range (tuple): A tuple specifying the range of ports to scan (start, end).
            
        Returns:
            list: A combined list of open ports found during the scans from both tools.
        
        Raises:
            ValueError: If scan_type is not supported.
            TypeError: If scan_type is not a string.
        """
        if not isinstance(scan_type, str):
            raise TypeError("scan_type must be a string.")
        
        open_ports = set()

        # Perform Scapy scan
        logger.info("🛠️ Starting Scapy scan...")
        with ThreadPoolExecutor(max_workers=100) as executor:
            if scan_type.lower() == 'tcp':
                futures = {executor.submit(self._scan_port_scapy, ip, port): port for port in range(*port_range)}
            elif scan_type.lower() == 'udp':
                futures = {executor.submit(self._udp_scan, ip, port): port for port in range(*port_range)}
            elif scan_type.lower() == 'xmas':
                futures = {executor.submit(self._xmas_scan, ip, port): port for port in range(*port_range)}
            else:
                raise ValueError("Scan type not supported. Use 'tcp', 'udp', or 'xmas'.")

            for future in tqdm(as_completed(futures), total=len(futures), desc=f"Scanning ports on {ip}"):
                port = futures[future]  # Get the port from the future
                try:
                    result = future.result()
                    if result[1] in ("Open", "Open / filtered"):
                        open_ports.add(port)
                except Exception as e:
                    logger.error(f"⚠️ Error scanning port {port} on {ip}: {e}")

        logger.info(f"🔍 Scapy scan completed on {ip}: {len(open_ports)} open ports found.")

        # Perform Nmap scan
        nmap_results = self._nmap_scan(ip)

        # Combine results from Nmap scan
        if nmap_results:
            # Iterate through the Nmap results to gather open ports
            for result in nmap_results.values():  # Iterate over the IP results
                if isinstance(result, dict) and 'ports' in result:
                    for port_info in result['ports']:
                        if port_info['state'] == 'open':
                            open_ports.add(int(port_info['portid']))  # Add open port to the set
                            logger.info(f"🔓 Port {port_info['portid']} is open on {ip} (Nmap).")

        logger.info(f"🔍 Combined scan results on {ip}: {len(open_ports)} total open ports found.")
        return sorted(open_ports)  # Return sorted list of open ports