import os
import json
import requests
import webbrowser
from datetime import datetime
from scapy.all import sniff, IP, TCP

# Function to detect phishing
def check_url(url):
    try:
        api_url = f"https://phishstats.info:2096/api/phishing?url={url}"
        response = requests.get(api_url, timeout=5)
        
        if response.ok:
            data = response.json()
            if isinstance(data, list) and len(data) > 0 and 'is_phishing' in data[0]:
                return data[0]['is_phishing']
            else:
                print("Unexpected response format.")
                return False
        else:
            print("Failed to get response from API.")
            return False
    except requests.RequestException as e:
        print(f"Error in API request: {e}")
        return False

# Network sniffing and packet capture
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Packet: {ip_layer.src} -> {ip_layer.dst}")
        return {"src": ip_layer.src, "dst": ip_layer.dst}

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")
        return {"src_port": tcp_layer.sport, "dst_port": tcp_layer.dport}

def start_sniffing(count=10):
    sniffed_data = sniff(prn=packet_callback, count=count)
    return [{"src": p[IP].src, "dst": p[IP].dst} for p in sniffed_data if p.haslayer(IP)]

# Evidence collection
def collect_evidence(data):
    evidence_path = "evidence.json"
    
    # Load existing evidence data, handling JSON decoding errors
    if os.path.exists(evidence_path):
        try:
            with open(evidence_path, "r") as f:
                evidence = json.load(f)
        except json.JSONDecodeError:
            print("Warning: evidence.json file is corrupted or invalid. Starting with an empty list.")
            evidence = []
    else:
        evidence = []

    evidence.append(data)

    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=4)

    print(f"Evidence collected: {data}")
    return data

# Complexity and energy consumption calculation

# Complexity and energy consumption calculation
def calculate_complexity(tools, loop_counts):
    complexity_data = {}
    for tool in tools:
        complexity_data[tool['name']] = {
            "time_complexity": f"O({loop_counts[0]})",  # For simplicity, assuming linear time complexity
            "space_complexity": f"O({loop_counts[1]})"  # Assuming linear space complexity for TCP packets
        }
    return complexity_data

def calculate_energy_consumption(processes, loop_counts):
    energy_data = {}
    for process in processes:
        duration = process.get("duration", 1)  # in hours
        power = process.get("power", 0.5)  # in kWh
        energy_data[process['name']] = {
            "energy_consumed": round(duration * power, 2),
            "duration": duration,
            "dynamic_energy": round(duration * power * (loop_counts[0] + loop_counts[1]), 2)
        }
    return energy_data

      
# Report generation
def generate_report(report_data):
    try:
        report_path = "report.html"
        
        phishing_data = report_data.get("phishing", [])
        phishing_table = "<p>No phishing data detected.</p>" if not phishing_data else \
            "<table><tr><th>URL</th><th>Status</th></tr>" + \
            "".join([f"<tr><td>{entry['url']}</td><td>{entry['status']}</td></tr>" for entry in phishing_data]) + \
            "</table>"
        
        network_data = report_data.get("network_analysis", [])
        network_table = "<p>No network data captured.</p>" if not network_data else \
            "<table><tr><th>Source</th><th>Destination</th></tr>" + \
            "".join([f"<tr><td>{entry['src']}</td><td>{entry['dst']}</td></tr>" for entry in network_data]) + \
            "</table>"
        
        evidence_data = report_data.get("evidence", [])
        evidence_table = "<table><tr><th>Type</th><th>Details</th></tr>" + \
            "".join([f"<tr><td>{entry['type']}</td><td>{json.dumps(entry['details'])}</td></tr>" for entry in evidence_data]) + \
            "</table>"

        tool_complexity = calculate_complexity(report_data.get("tools", []), report_data.get("loop_counts", [0, 0]))
        complexity_table = "<table><tr><th>Tool</th><th>Time Complexity</th><th>Space Complexity</th></tr>" + \
            "".join([f"<tr><td>{tool}</td><td>{data['time_complexity']}</td><td>{data['space_complexity']}</td></tr>" for tool, data in tool_complexity.items()]) + \
            "</table>"

        energy_consumption = calculate_energy_consumption(report_data.get("processes", []), report_data.get("loop_counts", [0, 0]))
        energy_table = "<table><tr><th>Process</th><th>Energy Consumed (kWh)</th><th>Duration (hours)</th><th>Dynamic Energy (kWh)</th></tr>" + \
            "".join([f"<tr><td>{process}</td><td>{data['energy_consumed']}</td><td>{data['duration']}</td><td>{data['dynamic_energy']}</td></tr>" for process, data in energy_consumption.items()]) + \
            "</table>"


        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cyber Forensics Report</title>
            <link rel="stylesheet" href="main.css">
        </head>
        <body>
            <div class="report-container">
                <header>
                    <h1>Cybercrime Detection and Analysis Report</h1>
                    <p><strong>Date:</strong> {report_data['report_date']}</p>
                    <p><strong>Case Number:</strong> {report_data['case_number']}</p>
                    <p><strong>Classification:</strong> {report_data['classification_level']}</p>
                </header>

                <section>
                    <h2>Executive Summary</h2>
                    <p>{report_data.get("executive_summary", "No executive summary available.")}</p>
                </section>

                <section>
                    <h2>Phishing Analysis</h2>
                    {phishing_table}
                </section>

                <section>
                    <h2>Network Analysis</h2>
                    {network_table}
                </section>

                <section>
                    <h2>Evidence Collection</h2>
                    {evidence_table}
                </section>

                <section>
                    <h2>Tools and Complexity</h2>
                    {complexity_table}
                </section>

                <section>
                    <h2>Energy Consumption</h2>
                    {energy_table}
                </section>

                <section>
                    <h2>Conclusions and Recommendations</h2>
                    <p>{report_data.get("conclusions_and_recommendations", "No conclusions available.")}</p>
                </section>

                <footer>
                    <p>&copy; {datetime.now().year} Cybercrime Investigation Unit. All rights reserved.</p>
                    <p>This report is confidential and intended for authorized personnel only.</p>
                </footer>
            </div>
        </body>
        </html>
        """

        with open(report_path, "w") as f:
            f.write(html_content)
        
        webbrowser.open(report_path)
        print(f"Report generated at {report_path}")

    except Exception as e:
        print(f"Error during report generation: {e}")

# Main function to run the tool
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
