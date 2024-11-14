import os
import json
import requests
import webbrowser
from datetime import datetime
from scapy.all import sniff, IP, TCP
from report_generator import generate_report
from evidence_collector import collect_evidence
from phishing_detection import check_url
from network_sniffer import start_sniffing

def main():
    print("Cybercrime Detection and Evidence Collection System")
    
    report_data = {
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "case_number": "CASE12345",
        "classification_level": "Confidential",
        "phishing": [],
        "network_analysis": [],
        "evidence": [],
        "tools": [
            {"name": "Sniffer", "time_complexity": "N", "space_complexity": "N"},
            {"name": "Phishing Detector", "time_complexity": "1", "space_complexity": "1"}
        ],
        "processes": [
            {"name": "Data Collection", "duration": 1, "power": 0.5},
            {"name": "Data Analysis", "duration": 2, "power": 0.7},
            {"name": "Report Generation", "duration": 0.5, "power": 0.3}
        ]
    }
    
    url = input("Enter a URL to check for phishing: ").strip()
    if url:
        is_phishing = check_url(url)
        if is_phishing:
            print("Phishing URL detected!")
            phishing_data = {"url": url, "status": "Phishing"}
            report_data["phishing"].append(phishing_data)
            report_data["evidence"].append(collect_evidence(phishing_data))
        else:
            print("URL is safe.")
    else:
        print("Invalid URL. Please try again.")
    
    print("Starting network sniffing...")
    report_data["network_analysis"] = start_sniffing(count=10)
    report_data["evidence"].append(collect_evidence({"type": "Network Analysis", "details": report_data["network_analysis"]}))
    
    report_data["executive_summary"] = "This report summarizes cybercrime detection activities and findings for the given case."
    report_data["conclusions_and_recommendations"] = "Increase cybersecurity measures and monitor network activity regularly."

    generate_report(report_data)

if __name__ == "__main__":
    main()
