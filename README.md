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
<img src="https://imgur.com/K6B0sYK.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the provided artefacts</b>
<br/>

<p align="center">
<img src="https://imgur.com/rGQ6lsl.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to see what the email's content.</b>
<br/>

<p align="center">
<img src="https://imgur.com/mYGT2Hk.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to text editor.</b>
<br/>

<p align="center">
<img src="https://imgur.com/Tm1zRyC.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Extraction of the .eml for IOCs.</b>
<br/>

<p align="center">
<img src="https://imgur.com/M2cPUtu.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers.</b>
<br/>

<p align="center">
<img src="https://imgur.com/gV31oQo.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Attachment Analysis.</b>
<br/>

<p align="center">
<img src="https://imgur.com/pTGp4HA.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/y9UlqZa.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Parse .lnk file and decode the base64 string.</b>
<br/>

<p align="center">
<img src="https://imgur.com/y9UlqZa.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/meomwvu.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Domains used by the attacker for file hosting and C2</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>The enumeration tool downloaded by the attacker</b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

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

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

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

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

<p align="center">
<img src="https://imgur.com/" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b></b>
<br/>

## Outcome

- Phishing Analysis Proficiency: Effectively dissect phishing emails, decode encoded attachments, and identify malicious payloads such as .HTA files or VBA macros.
 - Endpoint Investigation Skills: Investigate PowerShell logs, analyze the execution of malicious commands, and understand their impact on the system. Identify persistence mechanisms and escalate privileges techniques used by attackers.
 - Network Traffic Forensics: Perform in-depth analysis of packet captures, identify the domains, ports, and tools used by attackers for C2 communication, and reconstruct the attack’s network flow to understand the exfiltration process.
 - Data Exfiltration Detection: Correlating PowerShell logs and network traffic data, identify data exfiltration techniques, reconstruct stolen data, and understand how attackers bypass defenses to move sensitive data out of the compromised network.
 - Incident Response: Conduct full incident investigations, from email attachment extraction to network traffic examination, and respond effectively to similar phishing-based attacks in real-world environments.
 - Full Attack Lifecycle Understanding: The integration of file, endpoint, and network analysis techniques, learn to piece together a complete attack timeline, identifying key attack vectors, lateral movement, and data exfiltration methods, ability to detect and mitigate similar future attacks.
 - Advanced Analysis with ELK: Gain hands-on experience using the ELK Stack (ElasticSearch and Kibana) to search, analyze, and visualize data from various sources (e.g., PowerShell logs, Sysmon logs, network traffic) for detecting malicious activities, correlating events, and conducting comprehensive investigations.

## Acknowledgements
- Inspired from [TryHackMe - Boogeyman 1](https://tryhackme.com/r/room/boogeyman1)
- [Whois](https://www.whois.com/whois/)
