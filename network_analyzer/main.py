from core.network_analyzer import NetworkAnalyzer

def main():
    network_range = "192.168.11.0/24"
    timeout = 1

    # Initialize NetworkAnalyzer
    analyzer = NetworkAnalyzer(network_range, timeout)

    # Run a full scan
    results = analyzer.scan_ports(["192.168.11.128"])
    

    # Optionally, process or save the results
    print("Full scan completed!")
    print(results)

if __name__ == "__main__":
    main()