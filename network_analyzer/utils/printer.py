from rich.console import Console
from rich.table import Table

def print_table(data, data_type="hosts"):
    """Prints the scanning results in a structured table format."""
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")

    if data_type == "hosts":
        table.add_column("Hosts Up", style="bold green")
        for host in data:
            table.add_row(host, end_section=True)

    elif data_type == "ports":
        table.add_column("IP Address", style="bold green")
        table.add_column("Open Ports", style="bold blue")
        for ip, ports in data.items():
            ports_str = ', '.join(map(str, ports))
            table.add_row(ip, ports_str, end_section=True)

    elif data_type == "services":
        table.add_column("IP Address", style="bold green")
        table.add_column("Port", style="bold blue")
        table.add_column("Service", style="bold yellow")
        for ip, services in data.items():
            for port, service in services.items():
                table.add_row(ip, str(port), service, end_section=True)
    
    console.print(table)