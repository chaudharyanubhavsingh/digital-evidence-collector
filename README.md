
# CYBERCRIME DETECTION AND EVIDENCE COLLECTION SYSTEM

## Overview
This project is an advanced tool designed for cybersecurity investigations. It includes features for detecting phishing, analyzing network traffic, collecting evidence, and generating forensic-style reports. The system is tailored to assist cybersecurity professionals in identifying and mitigating potential threats effectively.

## Features
- **Phishing Detection**: Checks URLs for phishing threats using an external API.
- **Network Traffic Analysis**: Captures and analyzes packets to identify suspicious activity.
- **Evidence Collection**: Automatically collects and stores evidence in a structured format.
- **Report Generation**: Generates detailed HTML reports with visualizations and recommendations.
- **Complexity and Energy Analysis**: Provides insights into time complexity, space complexity, and energy consumption of tools and processes.

## Technologies Used
- **Programming Language**: Python
- **Libraries**:
  - `requests`: For API calls
  - `scapy`: For network sniffing and packet analysis
  - `datetime`: For timestamp management
  - `json`: For evidence storage and report data handling
  - `webbrowser`: To display generated reports
- **HTML & CSS**: For generating professional forensic reports

## How to Run
1. **Pre-requisites**:
   - Python 3.x installed on your system
   - Required libraries installed (`pip install -r requirements.txt`)

2. **Steps to Execute**:
   - Clone the repository: `git clone <repository-url>`
   - Navigate to the project directory: `cd <project-directory>`
   - Run the main script: `python main.py`

3. **Inputs**:
   - Enter a URL for phishing detection.
   - Allow network sniffing for packet analysis.

4. **Outputs**:
   - An HTML report will be generated in the project directory and automatically opened in your default browser.

## Time Complexity Analysis
- **Phishing Detection**: O(1) for single URL checks due to constant API interaction.
- **Network Sniffing**: O(N) where N is the number of packets captured and analyzed.
- **Report Generation**: O(M) where M is the number of data points to be included in the report.

## Energy Consumption Analysis
- **Processes Evaluated**:
  - Data Collection: Consumes minimal energy depending on packet count.
  - Data Analysis: Moderate energy consumption based on processing complexity.
  - Report Generation: Minimal energy as it primarily involves file handling.



## Files Included
- `main.py`: Main entry point of the application.
- `phishing_detection.py`: Module for URL phishing detection.
- `network_sniffer.py`: Module for capturing and analyzing network packets.
- `report_generator.py`: Module for generating forensic-style reports.
- `evidence_collector.py`: Module for evidence collection.
- `requirements.txt`: Dependencies required to run the project.
- `README.md`: Project documentation.

## Future Enhancements
- Integration with real-time monitoring tools.
- Addition of machine learning models for advanced threat detection.
- Multi-language support for wider usability.

## Disclaimer
This tool is intended for educational and ethical purposes only. Unauthorized use for malicious activities is strictly prohibited.

## Author
Developed by Anubhav Chaudhary.
