from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from fpdf import FPDF
import json

class AISecurityAnalyzer:
    """
    Class representing an AI agent capable of analyzing network scan results 
    and generating detailed reports on attack vectors, exploitation steps, 
    and security recommendations, including PDF and JSON reports.

    Attributes:
        model (ChatGroq): The Groq model used for analyzing and generating reports.
        prompt_template (ChatPromptTemplate): The template for the prompt to generate the analysis.
    """

    def __init__(self, model_id="llama3-70b-8192", groq_api_key=None):
        """
        Initializes the security analyzer with the specified Groq model and API key.
        
        Args:
            model_id (str): The ID of the Groq model to use. Default is 'llama3-70b-8192'.
            groq_api_key (str): The API key for accessing Groq services.
        """
        if not groq_api_key:
            raise ValueError("Groq API key must be provided either as an argument or an environment variable.")

        self.model = ChatGroq(model=model_id, temperature=0, api_key=groq_api_key)
        self.prompt_template = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """
                    You are an expert in cybersecurity, specializing in offensive and defensive techniques. 
                    Your task is to analyze the following network scan results and generate a detailed report that includes:

                    1. **Overall Security Assessment**: Provide an opinion on the current security state of the network.
                    2. **Detailed Service Analysis**:
                        - Identify the versions of services detected and assess whether they are vulnerable based on known CVEs.
                        - Explain the purpose of each service and whether it makes sense for it to be exposed externally.
                    3. **Potential Attack Vectors**: Based on the open ports and services, identify possible attack vectors that could be exploited.
                    4. **Recommendations for Exploitation**: Suggest steps for a penetration testing phase, including the tools or techniques to use.
                    5. **Mitigation Strategies**: Provide actionable recommendations to mitigate risks, including configuration changes, patching advice, and service exposure recommendations.
                    6. **Historical Context**: If available, note any changes in the exposure of services or vulnerabilities over time.
                    7. **Anomalies Detected**: Highlight any unexpected findings, such as open ports or services running on non-standard ports.

                    The input data will be provided in the following format:

                    "hosts": active_hosts,         # Active hosts discovered
                    "open_ports": open_ports,      # Open ports found
                    "services": services,          # Services and banners
                    "smb_shares": smb_shares       # SMB shares discovered

                    Provide a comprehensive analysis based on this information, including references to security advisories when applicable.
                    """
                ),
                ("human", "{scan_results}"),
            ]
        )

    def analyze_scan_results(self, scan_results, pdf_path="nethawk_security_report.pdf", json_path="nethawk_security_report.json"):
        """
        Generates a security analysis based on the provided scan results, and automatically
        generates both a PDF and JSON report as part of the process.
        
        Args:
            scan_results (dict): A dictionary containing network scan results.
            pdf_path (str): The file path to save the PDF report. Default is 'nethawk_security_report.pdf'.
            json_path (str): The file path to save the JSON report. Default is 'nethawk_security_report.json'.
        
        Returns:
            str: Generated report with analysis or None if an error occurs.
        """
        try:
            # Create a chain using the prompt template and the model
            chain = self.prompt_template | self.model
            # Invoke the chain with the provided scan results
            response = chain.invoke({"scan_results": scan_results})

            # Extract content from the response
            if hasattr(response, 'text'):
                analysis = response.text.strip()
            elif hasattr(response, 'content'):
                analysis = response.content.strip()
            else:
                raise TypeError("Unexpected response type: Unable to extract content.")

            # Step 1: Generate the PDF report
            self._generate_pdf_report(analysis, pdf_path)

            # Step 2: Generate the JSON report
            self._generate_json_report(scan_results, json_path)

            # Return the analysis text
            return analysis
        except Exception as e:
            print(f"Error generating security analysis: {e}")
            return None

    def _generate_pdf_report(self, analysis, file_path="security_report.pdf"):
        """
        Generates a PDF report from the analysis results.

        Args:
            analysis (str): The text analysis generated by the AI.
            file_path (str): The file path to save the PDF report. Default is 'security_report.pdf'.
        """
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Add title
            pdf.set_font("Arial", style='B', size=16)
            pdf.cell(200, 10, txt="NetHawk Security Report", ln=True, align='C')
            pdf.ln(10)
            
            # Set font for body text
            pdf.set_font("Arial", size=12)
            
            # Iterate over each line of the analysis
            for line in analysis.split('\n'):
                # Check if the line is a header (starts and ends with "**")
                if line.startswith("**") and line.endswith("**"):
                    # Strip the asterisks and print the header in bold
                    header_text = line[2:-2].strip()  # Remove leading and trailing '**'
                    pdf.set_font("Arial", style='B', size=12)  # Bold font for headers
                    pdf.multi_cell(0, 10, txt=header_text)     # Write the header
                    pdf.ln(2)  # Add a little space after the header
                    pdf.set_font("Arial", size=12)  # Return to normal font for body text
                else:
                    # For normal body text, print it normally
                    pdf.multi_cell(0, 10, txt=line)
                    pdf.ln(2)
            
            # Save the PDF to a file
            pdf.output(file_path)
            print(f"PDF report generated: {file_path}")
        
        except Exception as e:
            print(f"Error generating PDF report: {e}")


    def _generate_json_report(self, scan_results, analysis, file_path="security_report.json"):
        """
        Generates an enhanced JSON report that includes scan results and the full AI-generated analysis.

        Args:
            scan_results (dict): The scan results to be included in the JSON report.
            analysis (str): The text analysis generated by the AI.
            file_path (str): The file path to save the JSON report. Default is 'security_report.json'.
        """
        try:
           
            report = {
                "scan_results": scan_results,
                "analysis": analysis
            }

            with open(file_path, 'w') as json_file:
                json.dump(report, json_file, indent=4)

            print(f"Enhanced JSON report generated: {file_path}")

        except Exception as e:
            print(f"Error generating JSON report: {e}")


