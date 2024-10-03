import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

class NetworkAnalyzer:
    """Clase para analizar la disponibilidad de hosts en una red específica.

    Attributes:
        network_range (str): El rango de direcciones IP a escanear.
        timeout (int): El tiempo máximo en segundos para esperar por una respuesta de cada host.
    """

    def __init__(self, network_range, timeout=1):
        """Inicializa la instancia de NetworkAnalyzer con el rango de red y el tiempo de espera.

        Args:
            network_range (str): El rango de direcciones IP en notación CIDR (por ejemplo, '192.168.1.0/24').
            timeout (int, optional): El tiempo en segundos para esperar la respuesta de un socket. Default es 1.
        """
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        """Intenta conectar un socket a un IP y puerto especificado, detectando si el host está activo.

        Args:
            ip (str): La dirección IP del host a escanear.
            port (int): El puerto a utilizar para el escaneo.

        Returns:
            tuple: Una tupla que contiene la dirección IP del host y un booleano indicando si el host está activo.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (ip, True)
        except (socket.timeout, socket.error):
            return (ip, False)

    def hosts_scan(self, port):
        """Escanea el rango de red para detectar hosts activos utilizando un puerto especificado.

        Args:
            port (int): El puerto a utilizar para el escaneo de cada host en la red.

        Returns:
            list: Una lista de IPs de los hosts que están activos.
        """
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            # tqdm se usa para mostrar la barra de progreso durante el escaneo
            futures = {executor.submit(self._scan_host_sockets, str(host), port): host for host in tqdm(network.hosts(), desc="Escaneando hosts")}
            for future in tqdm(futures, desc="Obteniendo resultados"):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])
        return hosts_up

    def pretty_print(self, data, data_type="hosts"):
        """Imprime los datos de forma elegante en la consola utilizando tablas.

        Args:
            data (list): La lista de datos a imprimir.
            data_type (str, optional): El tipo de datos a imprimir (actualmente solo soporta 'hosts'). Default es 'hosts'.
        """
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")

        if data_type == "hosts":
            table.add_column("Hosts Up", style="bold green")
            for host in data:
                table.add_row(host, end_section=True)

        console.print(table)