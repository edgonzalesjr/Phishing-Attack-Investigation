## Objective
 
Analyze a phishing email and investigate a Windows-based compromise that involves powershell commands and data exfiltration, utilizing provided artefacts and tools.

### Skills Learned

- Email Analysis
  - Extracting metadata and attachments from .eml files.
  - Decoding and reconstructing encoded attachments using CLI and GUI tools.
- Endpoint Security Investigation
  - Parsing and analyzing Powershell logs to identify malicious commands.
  - Filtering relevant data from JSON logs using jq and other CLI tools.
- Network Traffic Analysis
  - Investigating packet captures using Wireshark.
  - Identifying malicious domains, ip address, and data exfiltration techniques.
- Threat Actor Profiling
  - Correlating findings with known TTPs of threat groups.
  - Assessing the impact of an attack on organizational security.

### Tools Used

- lnkparse: A Python tool used to parse Windows shortcut (.lnk) files, revealing the embedded commands and payload paths.
- Wireshark: A GUI-based network protocol analyzer for inspecting packet capture files and identifying malicious network activity.
- jq: A command-line JSON processor for filtering and parsing large JSON files, such as PowerShell logs, to focus on specific entries or commands.
- Thunderbird: An open-source email client used to open and analyze the contents of the phishing email (dump.eml), including attachments.
- Command-Line Tools (grep, base64): These tools will assist in manually decoding and processing email data, including extracting base64-encoded payloads.

## Perform Analysis

<p align="center">
<img src="https://imgur.com/K6B0sYK.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the provided artefacts.</b>
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
<b>Domains used by the attacker for file hosting and C2.</b>
<br/>

<p align="center">
<img src="https://imgur.com/0iYW973.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>The enumeration tool downloaded by the attacker.</b>
<br/>

<p align="center">
<img src="https://imgur.com/APYmkn7.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>The file accessed by the attacker using the downloaded binary.</b>
<br/>

<p align="center">
<img src="https://imgur.com/IcV6ip4.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>The name of the exfiltrated file.</b>
<br/>

<p align="center">
<img src="https://imgur.com/gmmBMDK.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Software is used by the attacker to host it's presumed file/payload server.</b>
<br/>

<p align="center">
<img src="https://imgur.com/eLWob4J.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Protocol used during the exfiltration activity.</b>
<br/>

## Outcome

- Phishing Analysis: Dissect and analyze phishing emails, understand how malicious attachments are hidden, and successfully extract embedded payloads.
- Endpoint Investigation: Investigate Powershell logs (in JSON format) to understand the attacker’s methods, identify executed commands, and uncover their impacts on the compromised system.
- Network Traffic Forensics: Analyze packet captures to track the exfiltration process, including identifying the tools and techniques used by the attacker to send sensitive data out of the network.
- Data Exfiltration Detection: By correlating Powershell logs with network traffic, understand how the attacker exfiltrated data, how it was encoded, and how to reconstruct the stolen data using network traffic.
- Incident Response: By completing the analysis from email attachment extraction through to network traffic examination, uderstand how to conduct a full incident investigation, from initial compromise to data exfiltration, equip to respond to similar real-world incidents.

## Acknowledgements
- Inspired from [TryHackMe - Boogeyman 1](https://tryhackme.com/r/room/boogeyman1)
- [Wireshark](https://www.whois.com/whois/)
- [Thunderbird](https://www.whois.com/whois/)
- [lnkparse](https://github.com/Matmaus/LnkParse3)
