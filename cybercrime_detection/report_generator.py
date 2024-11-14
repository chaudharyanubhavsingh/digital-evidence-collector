import os
import json
import webbrowser
from datetime import datetime
def generate_report(report_data):
    try:
        # Path to the report file
        report_path = "report.html"

        # Remove the previous report if it exists
        if os.path.exists(report_path):
            os.remove(report_path)

        # Ensure the data is present and handle missing data gracefully
        phishing_data = json.dumps(report_data.get("phishing", []), indent=4) if "phishing" in report_data else "No phishing data available"
        network_data = json.dumps(report_data.get("network_analysis", []), indent=4) if "network_analysis" in report_data else "No network analysis data available"
        evidence_data = json.dumps(report_data.get("evidence", []), indent=4) if "evidence" in report_data else "No evidence collected"

        # Create the new report
        with open(report_path, "w") as f:
            f.write(f"""
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
            <p><strong>Date:</strong> {report_date}</p>
            <p><strong>Case Number:</strong> {case_number}</p>
            <p><strong>Classification:</strong> {classification_level}</p>
        </header>

        <section class="section">
            <h2>1. Executive Summary</h2>
            <p>{executive_summary}</p>
        </section>

        <section class="section">
            <h2>2. Incident Overview</h2>
            <p><strong>Date of Detection:</strong> {detection_date}</p>
            <p><strong>Detection Method:</strong> {detection_method}</p>
            <p><strong>Initial Indicators:</strong> {initial_indicators}</p>
        </section>

        <section class="section">
            <h2>3. Attack Classification</h2>
            <p><strong>Type of Attack:</strong> <span class="attack-classification">{attack_type}</span></p>
            <p><strong>Severity Level:</strong> {severity_level}</p>
            <p><strong>Potential Impact:</strong> {potential_impact}</p>
        </section>

        <section class="section">
            <h2>4. Evidence Collection</h2>
            <div class="evidence-item">
                <h3>4.1 Network Logs</h3>
                <p>{network_logs}</p>
                <p class="timestamp">Collected at: {network_logs_timestamp}</p>
            </div>
            <div class="evidence-item">
                <h3>4.2 System Artifacts</h3>
                <p>{system_artifacts}</p>
                <p class="timestamp">Collected at: {system_artifacts_timestamp}</p>
            </div>
            <div class="evidence-item">
                <h3>4.3 Malware Samples</h3>
                <p>{malware_samples}</p>
                <p class="timestamp">Collected at: {malware_samples_timestamp}</p>
            </div>
        </section>

        <section class="section">
            <h2>5. Phishing Analysis</h2>
            <p><strong>Suspected Phishing URLs:</strong> {phishing_urls}</p>
            <p><strong>Email Headers:</strong> {email_headers}</p>
            <p><strong>Attachment Analysis:</strong> {attachment_analysis}</p>
        </section>

        <section class="section">
            <h2>6. Tools Used</h2>
            <table>
                <tr>
                    <th>Tool Name</th>
                    <th>Version</th>
                    <th>Purpose</th>
                </tr>
                <tr>
                    <td>{tool_1_name}</td>
                    <td>{tool_1_version}</td>
                    <td>{tool_1_purpose}</td>
                </tr>
                <tr>
                    <td>{tool_2_name}</td>
                    <td>{tool_2_version}</td>
                    <td>{tool_2_purpose}</td>
                </tr>
                <tr>
                    <td>{tool_3_name}</td>
                    <td>{tool_3_version}</td>
                    <td>{tool_3_purpose}</td>
                </tr>
            </table>
        </section>

        <section class="section">
            <h2>7. Complexity Analysis</h2>
            <div class="analysis-item">
                <h3>7.1 Time Complexity</h3>
                <p>{time_complexity_analysis}</p>
            </div>
            <div class="analysis-item">
                <h3>7.2 Space Complexity</h3>
                <p>{space_complexity_analysis}</p>
            </div>
        </section>

        <section class="section">
            <h2>8. Energy Consumption</h2>
            <table>
                <tr>
                    <th>Process</th>
                    <th>Energy Consumed (kWh)</th>
                    <th>Duration (hours)</th>
                </tr>
                <tr>
                    <td>Data Collection</td>
                    <td>{data_collection_energy}</td>
                    <td>{data_collection_duration}</td>
                </tr>
                <tr>
                    <td>Data Analysis</td>
                    <td>{data_analysis_energy}</td>
                    <td>{data_analysis_duration}</td>
                </tr>
                <tr>
                    <td>Report Generation</td>
                    <td>{report_generation_energy}</td>
                    <td>{report_generation_duration}</td>
                </tr>
            </table>
        </section>

        <section class="section">
            <h2>9. Automated Analysis Results</h2>
            <p><strong>Threat Intelligence Matches:</strong> {threat_intelligence_matches}</p>
            <p><strong>Behavioral Analysis:</strong> {behavioral_analysis}</p>
            <p><strong>Machine Learning Classification:</strong> {ml_classification}</p>
        </section>

        <section class="section">
            <h2>10. Conclusions and Recommendations</h2>
            <p>{conclusions_and_recommendations}</p>
        </section>

        <section class="section">
            <h2>11. Investigator Notes</h2>
            <p>{investigator_notes}</p>
        </section>

        <div class="digital-signature">
            <p><strong>Lead Investigator:</strong> {lead_investigator_name}</p>
            <p><strong>Digital Signature:</strong> {digital_signature_placeholder}</p>
        </div>

        <div class="footer">
            <p>&copy; {current_year} Cybercrime Investigation Unit. All rights reserved.</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>
            """)

        # Open the report in the default web browser
        webbrowser.open(report_path)

    except Exception as e:
        print(f"Error during report generation: {e}")