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

### Tools Used

- lnkparse: A Python tool for parsing Windows shortcut (.lnk) files, revealing the commands and payload paths that trigger the execution of malicious payloads.
- Wireshark: A GUI-based network protocol analyzer for inspecting packet capture files (.pcap) to detect suspicious network activity and data exfiltration.
- Tshark: A command-line version of Wireshark, ideal for quickly extracting specific data from large packet capture files.
- jq: A powerful command-line tool used to process and filter large JSON files (such as PowerShell logs) for specific information about attacker activity.
- Thunderbird: An open-source email client used to open, analyze, and extract attachments from phishing emails (.eml format).
- Command-Line Tools (grep, sed, awk, base64): These tools assist in decoding and processing data within email files, such as base64-encoded payloads.
- Olevba: A tool for extracting and analyzing VBA macros embedded in Microsoft Office documents to detect malicious behavior.
- Volatility: A memory forensics tool used to extract and analyze data from system memory dumps, helping to uncover running processes, network activity, and persistence mechanisms.
- Sysmon and Windows Event Logs: Used to collect detailed system activity and security event logs for detecting malicious activities like lateral movement, credential harvesting, and persistence creation.

## Perform Analysis

- Phishing Email with .lnk or a Windows shortcut attachment
<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

- Phishing Email with .doc attachment that contains vba macro
<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

- Phishing Email with .hta (HTML application) attachment
<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>
