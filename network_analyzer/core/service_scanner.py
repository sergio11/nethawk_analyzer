from concurrent.futures import ThreadPoolExecutor
import socket
from tqdm import tqdm


class ServiceScanner:
    def __init__(self, timeout=1):
        """Initialize the service scanner with a timeout."""
        self.timeout = timeout

    def get_banner(self, ip, port):
        """Retrieves the banner from a specific service running on a host.

        Args:
            ip (str): IP address of the host.
            port (int): Port of the service.

        Returns:
            str: Banner of the service or error message.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                s.send(b'Hello\r\n')
                return s.recv(1024).decode().strip()
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None  # Return None for timeouts or refused connections
        except Exception as e:
            return str(e)

    def scan_services(self, ip, port_range=(0, 10000)):
        """Scans services on open ports of a host and retrieves banners.

        Args:
            ip (str): IP address of the host to scan.
            port_range (tuple): Range of ports to scan.

        Returns:
            dict: Dictionary of open ports and their corresponding banners.
        """
        services = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in tqdm(range(*port_range), desc=f"Retrieving banners on {ip}"):
                future = executor.submit(self.get_banner, ip, port)
                futures.append((future, port))

            for future, port in futures:
                result = future.result()
                # Include the same validations as the original method
                if result and 'timed out' not in result and 'refused' not in result and 'No route to host' not in result:
                    services[port] = result

        return services