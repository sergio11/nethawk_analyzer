import os
from NetHawkAnalyzer.analyzer import NetHawkAnalyzer
from dotenv import load_dotenv

def main():

    load_dotenv()

    groq_api_key = os.getenv("GROQ_API_KEY")
    model_id = os.getenv("MODEL_ID")
 
    # Initialize NetworkAnalyzer
    analyzer = NetHawkAnalyzer(
        network_range="192.168.11.0/24", 
        groq_api_key=groq_api_key, 
        model_id=model_id
    )
    
    # Run a full scan
    results = analyzer.run_full_scan()
    
    # Optionally, process or save the results
    print("Full scan completed!")
    print(results)

if __name__ == "__main__":
    main()