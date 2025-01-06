## Objective
 
Investigate and analyze a phishing attack, focusing on endpoint behavior, credential harvesting, lateral movement, and data exfiltration. This includes examining phishing email attachments (e.g., .HTA, .doc, .lnk), analyzing PowerShell execution logs, utilizing memory forensics, and performing network traffic analysis to uncover attacker activity.

### Skills Learned

- Phishing Email Analysis: Learn to identify phishing emails, analyze email headers, decode encoded attachments, and extract embedded malicious payloads (e.g., .HTA, .doc with VBA macros, Windows shortcut files).
- PowerShell Log Analysis: Understand how to analyze PowerShell execution logs (in JSON format) to track the execution of malicious commands, identify attacker activities, and uncover system compromise techniques.
- File Analysis and Forensics:
  - .LNK File Analysis: Use forensic tools to parse Windows shortcut files (.lnk) and identify embedded commands or payload paths.
  - VBA Macro Analysis: Extract and analyze VBA macros in Office documents using specialized tools like Olevba to reveal how the attacker uses them for C2 communication and payload execution.
- Memory Forensics: Gain expertise in using Volatility to perform memory analysis, identifying active processes, network connections, and artifacts left behind by attackers in system memory.
- Persistence Mechanism Detection: Learn to identify persistence mechanisms such as scheduled tasks and credential dumping techniques used by attackers to maintain access to compromised systems.
- Network Traffic and Data Exfiltration Detection: Use packet capture analysis tools like Wireshark and Tshark to trace the exfiltration of sensitive data, identifying attacker’s C2 channels, domains, ports, and exfiltration methods.
- ELK Stack for Log Analysis: Develop proficiency in using Elastic Search with Kibana for searching, analyzing, and visualizing large datasets (network logs, PowerShell logs, Windows Event Logs) to detect anomalies, lateral movement, and data exfiltration activities.
