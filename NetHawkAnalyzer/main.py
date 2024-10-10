from api.net_hawk_analyzer import NetHawkAnalyzer

def main():
    network_range = "192.168.11.0/24"
    timeout = 1

    # Initialize NetworkAnalyzer
    analyzer = NetHawkAnalyzer(network_range, timeout)

    # Run a full scan
    results = analyzer.run_full_scan()
    

    # Optionally, process or save the results
    print("Full scan completed!")
    print(results)

if __name__ == "__main__":
    main()