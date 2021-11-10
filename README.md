# BlackHat-Arsenal-2021-EU
Repo-Links to BlackHat Arsenal 2021 EU(Links are in the detail area)

Notify me if I miss some repo to a presentation or you find some, thanks.

## Presentations with Repo-Links

<details>
  <summary>WhoC: Peeking Under the Hood of CaaS Offerings</summary>
  
Running your business-critical applications on the public cloud involves trust. You trust your cloud provider to separate your workloads from other customers' workloads. You trust your cloud provider to patch and update their software and hardware stack. For those of us with trust issues, blindly running our applications in the public cloud can be tough. Fortunately, trust can be earned through visibility, and that's where WhoC can help. WhoC provides a bit of visibility into how Container-as-a-Service (CaaS) offerings run our containers.

WhoC (Who Contains) is a container image that upon execution extracts the underlying container runtime. It doesn't try to identify the underlying runtime based on the container's cgroup configuration, the existence of a '.dockerenv' file or any other known trick. WhoC exfiltrates the actual container runtime binary from the underlying host.

In this talk Yuval will walk you through how WhoC works and show a demo in a popular CaaS offering. You'll learn a surprising truth: Linux containers can actually access one host file - the container runtime. 
  
  [https://github.com/twistlock/whoc](WhoC)

</details>

<details>
  <summary>Slips: A Machine-Learning Based, Free-Software, Network Intrusion Prevention System</summary>
  
Slips is a behavioral-based intrusion prevention system, and the first free software to use machine learning to detect attacks in the network. It is a modular system that profiles the behavior of IP addresses and performs detections in time windows. Slips' modules detect a range of attacks both to and from the protected device. Slips connects to other Slips using P2P, and exports alerts to other systems.

Slips works in several directionality modes. The concept of home network is not used to choose which detection to apply, but to choose which profile to analyze. The user can choose to detect attacks coming *to* or going *from* these profiles. This makes it easy to protect your network but also to focus on infected computers inside your network.

Among its modules, Slips includes the download/manage of external Threat Intelligence feed (including our laboratory's own TI feed), whois/asn/geocountry enrichment, a LSTM neural net for malicious behavior detection, port scanning detection (vertical and horizontal) on flows, long connection detection, etc. The decisions to block profiles or not are based on ensembling
algorithms. The P2P module connects to other Slips to share detection alerts.

Slips can read packets from the network, pcap, Suricata, Zeek, Argus and Nfdump, and can output alerts files and summaries. Having Zeek as a base tool, Slips can correctly build a sorted timeline of flows combining all Zeek logs. Slips can send alerts using the STIX/TAXII protocol.

More importantly, the Kalipso Node.js interface allows the analysts to see the profiles' behaviors and detections performed by Slips modules directly in the console. Kalipso displays the flows of each profile and time window and compares those connections in charts/bars. It also summarizes the whois/asn/geocountry information for each IP that communicates with a protected device.

  
  [https://github.com/stratosphereips/StratosphereLinuxIPS](Slips)

</details>

<details>
  <summary>RIoTPot: A Modular Hybrid-Interaction IoT/OT Honeypot</summary>
  
  With attacks against Internet of Things (IoT) and Operational Technology (OT) protocols increasing, we need proper defensive tools as well as methods for studying adversarial techniques. RIoTPot is a novel IoT/OT honeypot that is written in Go and moves beyond the traditional binary world of low vs. high interaction level. It achieves this via a modular architecture that allows for hybrid deployment of low-interaction along with high-interaction components (based on containerization techniques) as per users' preferences. RIoTPot emulates a multitude of common IoT and OT protocols such as CoAP, MQTT, Modbus, Telnet, AMQP, SSH, HTTP and UPnP.
  
  [https://github.com/aau-network-security/riotpot](RIoTPot)

</details>

<details>
  <summary>Dependency Combobulator</summary>
  The Dependency Combobulator is a modular and extensible framework to detect and prevent dependency confusion leakage and potential attacks. This facilitates a holistic approach for ensure secure application releases that can be evaluated against different sources (e.g., GitHub, Artifactory) and many package management schemes (e.g., ndm, pip, maven).

The framework can be used by security auditors, pentesters and even baked into an enterprise's application security program and release cycle in an automated fashion.
 
  https://pythonrepo.com/repo/apiiro-combobulator-python-security

</details>

<details>
  <summary>Wireshark Forensics Toolkit</summary>
  
  Wireshark is the most widely used network traffic analyzer. It is an important tool for both live traffic analysis & forensic analysis for forensic/malware analysts. Even though Wireshark provides incredibly powerful functionalities for protocol parsing & filtering, it does not provide any contextual information about network endpoints. For a typical analyst, who has to comb through GBs of PCAP files to identify malicious activity, it's like finding a needle in a haystack.

Wireshark Forensics Toolkit is a cross-platform Wireshark plugin that correlates network traffic data with threat intelligence, asset categorization & vulnerability data to speed up network forensic analysis. It does it by extending Wireshark native search filter functionality to allow filtering based on these additional contextual attributes. It works with both PCAP files and real-time traffic captures.

This toolkit provides the following functionality
- Loads malicious Indicators CSV exported from Threat Intelligence Platforms like MISP and associates it with each source/destination IP from network traffic
- Loads asset classification information based on IP-Range to Asset Type mapping which enables filtering incoming/outgoing traffic from a specific type of assets (e.g. filter for 'Database Server', 'Employee Laptop' etc)
- Loads exported vulnerability scan information exported from Qualys/Nessus map IP to CVEs.
- Extends native Wireshark filter functionality to allow filtering based severity, source, asset type & CVE information for each source or destination IP address in network logs

[https://github.com/rjbhide/wireshark-forensics-plugin](wireshark-forensics-plugin)
</details>


<details>
  <summary>AADInternals: The Swiss Army Knife for Azure AD & M365</summary>
  
AADInternals is a popular attacking and administration toolkit for Azure Active Directory and Microsoft 365, used by red and blue teamers worldwide. The toolkit is written in PowerShell, making it easy to install and use by anyone familiar with the Microsoft ecosystem.

With AADInternals, one can create backdoors, perform elevation of privilege and denial-of-service attacks, extract information, and even bypass multi-factor authentication (MFA).

Join this session to see in action the research results conducted during the past two years, including a new technique to extract AD FS signing certificates remotely.
  
https://github.com/Gerenios/AADInternals

</details>


<details>
  <summary></summary>
  
</details>

## Missing Repo-Links

<details>
  <summary>The Vulnerability Complete Definition Library</summary>
  
More and more security researchers treat source code as a database and use code patterns to search or query potential vulnerabilities. At the Black Hat 2021 USA conference, the 360 ​​Alpha Lab team disclosed how to use code patterns to find 11 CVEs on Chrome, and developed a 0day exploit based on this. The code pattern is essentially a set of conditions for the code, and the code that satisfies certain conditions is very likely to have vulnerabilities. However, the industry does not seem to have a publicly available tool that can accurately describe or define the necessary and sufficient conditions for a specific vulnerability. Although CodeQL (https://securitylab.github.com/tools/codeql/) is already trying to convert the vulnerability described in natural language in Common Weakness Enumeration (https://cwe.mitre.org/) into query sentences , But most of its query conditions are sufficient and non-essential conditions to form a specific vulnerability, that is, it does not include all the circumstances that form this vulnerability. These query sentences avoid the conditions that CodeQL is difficult to process or describe to improve the success rate of the query. And I personally think that the grammatical rules of SQL often cannot intuitively describe the constraints of the code and the code running process, and a large number of built-in query processes also make the learning cost higher.

Therefore, I have developed a complete definition library for vulnerabilities and believe that this library has two main advantages. First, this library can describe constraints with syntax, design ideas, and keywords similar to the code used by developers, which makes this tool have a lower learning cost. Second, this library is designed to describe the necessary and sufficient conditions for the formation of vulnerabilities. The necessary and sufficient conditions here is used to describe all possible situations that form the vulnerabilities. We should not artificially modify the search conditions to make it easier for the algorithm of the search program to search for results, but should let the search algorithm determine by itself how to search can speed up the display of results.

This library is developed based on LLVM's AST (Abstract Syntax Tree) and the constraint solver STP (Simple Theorem Prover), and supports the description of constraints on objects such as control flow, data flow, value size, variable relations, variable types, variable names, etc. The library will also contain a batch of vulnerability definitions I wrote and a simple search algorithm. I will use a simple example to demonstrate how the algorithm finds a vulnerability in a specific situation based on the vulnerability definition. All source code will be hosted on github, you can download and study by yourself.  

</details>

<details>
  <summary>Disrupting OT and IoT by Exploiting TCP/IP Stacks</summary>
  
We will demonstrate an attacker’s journey to disrupt a model smart building - which could be a residence, an office, or any critical facility like a hospital - using only TCP/IP stack vulnerabilities, which are known to affect large numbers of devices at a time.

Attendees will interact with a tool to identify the TCP/IP stack running on a target device (using techniques such as banner grabbing, ICMP querying and TCP fingerprinting), a static analysis tool to find DNS-based vulnerabilities on TCP/IP stacks, and finally an exploit scenario involving a DNS-based RCE on a development board, an FTP-based DoS on a PLC and a TCP-based DoS on the switch connecting them.

The physical effects on the model building include switching on or off lighting and ventilation systems. We will also discuss how a similar exploit scenario can lead to other types of physical effects in critical infrastructure.

</details>

<details>
  <summary></summary>
  
</details>




