# Multi-Stage Windows Intrusion Investigation

## Executive Summary

This project documents a simulated Windows incident investigation involving a multi-stage compromise that progressed from malicious document execution through command and control, reconnaissance, tunneling, privilege escalation, and persistent administrative access.

The investigation correlated Sysmon telemetry, Windows Security events, and network traffic to reconstruct the attack sequence across the compromised endpoint. Key findings included execution initiated through a malicious Microsoft Word document, abuse of `msdt.exe` and encoded PowerShell, payload placement in a Startup location, HTTP-based command-and-control activity, deployment of a Chisel reverse SOCKS proxy, privilege escalation involving `SeImpersonatePrivilege`, SYSTEM-level execution, and creation of persistent local administrative accounts.

The focus of this case study is not individual alert identification, but reconstruction of the intrusion as a connected sequence of attacker behaviors supported by multiple evidence sources.

## Investigation Scope

The investigation focused on reconstructing attacker activity on a compromised Windows endpoint and answering several core incident-response questions:

- How did malicious execution begin?
- What processes and payloads were involved?
- How was persistence established?
- What command-and-control infrastructure was contacted?
- What reconnaissance was performed after compromise?
- How was tunneling used to support additional access?
- How did the attacker escalate privileges?
- What evidence showed SYSTEM-level execution?
- What accounts or access mechanisms were created for persistence?

The investigation followed the attack from initial execution through post-exploitation and account manipulation rather than treating each artifact as an isolated event.

The environment was a simulated training scenario. Findings are presented as an analyst investigation and are limited to behaviors supported by the preserved forensic evidence.

## Evidence Sources and Tools

### Evidence Sources

The investigation used multiple telemetry sources to reconstruct the intrusion:

- Sysmon event logs
- Windows Security event logs
- packet-capture data
- process creation records
- command-line arguments
- network connection evidence
- DNS and HTTP traffic
- account-management events
- group-membership changes

Each source provided a different view of the compromise.

Sysmon was particularly useful for reconstructing process relationships, command execution, file creation, and attacker tooling.

Windows Security events provided evidence of account creation, account changes, password activity, and modification of privileged group membership.

Network evidence was used to identify command-and-control infrastructure, HTTP communication, tunneling activity, and other external connections.

### Analysis Tools

Tools used during the investigation included:

- EvtxECmd
- Timeline Explorer
- Wireshark
- Brim
- Windows Event Viewer
- PowerShell

The combination of endpoint and network analysis allowed findings to be validated across independent data sources where possible.

## Attack Overview

The intrusion began when a malicious Microsoft Word document triggered a child-process chain involving `msdt.exe` and encoded PowerShell.

The attacker then retrieved additional payloads, established persistence through the Windows Startup mechanism, and began communicating with external command-and-control infrastructure.

Post-compromise activity included reconnaissance, tunneling through a Chisel reverse SOCKS proxy, and privilege escalation. Following escalation, SYSTEM-level execution was established and additional local accounts were created and modified to preserve administrative access.

At a high level, the intrusion progressed as follows:

```text
Malicious Word document
        ↓
WINWORD.EXE
        ↓
msdt.exe
        ↓
Encoded PowerShell
        ↓
Stage 2 payload
        ↓
Startup persistence
        ↓
HTTP command and control
        ↓
Internal reconnaissance
        ↓
Chisel reverse SOCKS proxy
        ↓
Privilege escalation
        ↓
SYSTEM-level execution
        ↓
Local account creation
        ↓
Administrators group membership
        ↓
Persistent access
```

The sections below examine each stage using the preserved endpoint and network evidence.

## Initial Execution

### Malicious Document

![Malicious Word document execution](evidence/01-malicious-document-execution.png)

*Figure 1 — Sysmon process evidence showing Microsoft Word opening the malicious `free_magicules.doc` document.*

The investigation began with a malicious Microsoft Word document associated with the initial compromise.

Endpoint telemetry showed Microsoft Word launching a suspicious child-process chain rather than behaving like a normal document-viewing session.

The relevant progression was:

```text
Malicious Word document
        ↓
WINWORD.EXE
        ↓
msdt.exe
        ↓
PowerShell
```

The relationship between `WINWORD.EXE` and the subsequent system utilities was important because the presence of `msdt.exe` or PowerShell alone would not necessarily indicate malicious activity.

The significance came from their appearance directly beneath the document process in the execution chain.

This provided the first strong evidence that opening the document resulted in attacker-controlled code execution on the endpoint.

### MSDT and Encoded PowerShell

![MSDT and encoded PowerShell execution](evidence/02-msdt-encoded-powershell.png)

*Figure 2 — Sysmon command-line evidence showing `msdt.exe` invoked with PCWDiagnostic parameters and an embedded encoded PowerShell expression.*

The process chain showed abuse of `msdt.exe`, followed by PowerShell containing encoded command content.

Encoded PowerShell can be used legitimately, but it is also commonly used to obscure scripts or commands from casual inspection.

In this investigation, its placement directly after the suspicious Word/MSDT sequence made it part of the confirmed malicious execution chain.

The sequence can be summarized as:

```text
WINWORD.EXE
      ↓
msdt.exe
      ↓
Encoded PowerShell
      ↓
Attacker-controlled execution
```

The encoded PowerShell activity provided the bridge between initial document execution and retrieval of the next stage of the intrusion.

The investigation therefore treated the Word process tree as a connected execution chain rather than as several unrelated Windows processes.

## Stage 2 Payload and Persistence

### Payload Delivery

![PowerShell payload download](evidence/03-powershell-payload-download.png)

*Figure 3 — Decoded PowerShell showing retrieval and extraction of `update.zip` from attacker-controlled infrastructure into the Windows Startup directory.*

Decoding the PowerShell command revealed a download-and-extraction sequence targeting phishteam.xyz.

The command retrieved update.zip, extracted its contents into the user's Windows Startup directory, and removed the downloaded archive.

Sysmon file-creation evidence subsequently identified update.lnk in that location.

This connected the initial document execution to the installation of the persistence mechanism.

### Startup Persistence

![Windows Startup persistence](evidence/04-startup-persistence.png)

*Figure 4 — Sysmon Event ID 11 recording creation of `update.lnk` in the user's Startup folder.*

The attacker established persistence by placing attacker-controlled content within a Windows Startup location.

Artifacts showed files associated with the intrusion being written into a path that causes content to execute when a user signs in.

This created a persistence mechanism independent of the original malicious Word document.

The progression was:

```text
Downloaded payload
        ↓
Startup location
        ↓
User logon
        ↓
Automatic execution
```

Persistence through Startup folders is significant because it can survive the termination of the original process chain and allow attacker-controlled code to execute again during later user sessions.

The investigation treated file placement and execution as separate questions. The presence of a file in the Startup location established the persistence mechanism, while subsequent process evidence was used where available to determine whether the payload later executed.

### Stage 2 Significance

By the end of this stage, the attacker had moved beyond one-time document execution.

The compromise now included:

- a second-stage payload,
- use of legitimate Windows tooling for file retrieval,
- and a persistence mechanism capable of surviving the initial execution session.

This established the foundation for the later command-and-control, reconnaissance, tunneling, and privilege-escalation activity observed in the remainder of the investigation.

## Command and Control

Following the initial malicious document execution and establishment of Startup persistence, the investigation shifted to network telemetry to identify external communication associated with the compromised endpoint.

Packet-capture analysis provided visibility into outbound connections, HTTP requests, destination infrastructure, and client-identification strings. These artifacts helped connect the endpoint execution chain to the attacker's command-and-control (C2) activity.

### C2 Infrastructure

Network analysis identified communication involving the external domain:

```text
resolvecyber.xyz
```

The domain was investigated in the context of the suspicious endpoint activity rather than being classified as malicious based on its name alone.

The surrounding attack sequence established that the endpoint had already executed attacker-controlled code, retrieved additional payloads, and created a persistence artifact. Subsequent communication with the external infrastructure was therefore treated as potentially related to the ongoing intrusion.

The investigation distinguished between the earlier payload-delivery infrastructure and the infrastructure observed during subsequent C2 activity.

![Repeated outbound connections in Sysmon](evidence/05-sysmon-c2-connections.png)

*Figure 5 — Sysmon network telemetry showing repeated outbound connections to `167.71.222.162` from the same process context.*

### HTTP Communication

The packet capture contained HTTP activity associated with the compromised endpoint.

Review of HTTP requests and related network metadata provided visibility into the external destination and application-layer communication behavior.

This complemented the Sysmon investigation:

```text
Malicious document execution
        ↓
PowerShell payload retrieval
        ↓
Startup persistence
        ↓
Suspicious HTTP communication
        ↓
C2-related activity
```

The HTTP evidence was examined alongside endpoint artifacts to determine how the network activity fit into the broader attack sequence.

Where request or response content was available, it provided additional context about the activity. Network connections alone were not treated as proof of the exact commands executed on the endpoint.

![HTTP command-and-control traffic in Brim](evidence/06-http-c2-traffic.png)

*Figure 6 — Brim analysis showing repeated HTTP GET requests to `resolvecyber.xyz`, including variable query-string content and the `Nim httpclient/1.6.6` User-Agent.*

### User-Agent Analysis

One distinctive network artifact was the HTTP User-Agent:

```text
Nim httpclient/1.6.6
```

This value indicated that the HTTP client identified itself as a Nim HTTP client rather than a conventional web browser.

The User-Agent was useful because it could help distinguish suspicious application-generated requests from ordinary interactive browsing.

However, User-Agent strings are client-controlled and can be modified or spoofed. The value was therefore treated as an investigative indicator rather than definitive proof of the software responsible for the communication.

Its significance came from the correlation between the unusual HTTP client behavior and the independently identified malicious endpoint activity.

### C2 Investigation Findings

The network investigation established several important findings:

1. The compromised environment contained suspicious HTTP communication associated with external infrastructure.
2. `resolvecyber.xyz` was identified during investigation of the attacker's network activity.
3. The `Nim httpclient/1.6.6` User-Agent provided an additional indicator for identifying related requests.
4. Network evidence complemented the endpoint execution and persistence findings, strengthening reconstruction of the ongoing compromise.

The combination of endpoint and network telemetry supported the assessment that the intrusion had progressed beyond initial execution into sustained attacker communication.

The investigation then continued into internal reconnaissance, tunneling, and other post-compromise activity.

## Internal Reconnaissance

### Credential Discovery
### Service and Port Enumeration

## Tunneling and Remote Access

### Chisel Reverse SOCKS Proxy
### Remote Authentication Activity

## Privilege Escalation

### SeImpersonatePrivilege
### SYSTEM-Level Access

## Persistence and Account Manipulation

### Local Account Creation
### Administrator Group Membership
### Additional Persistent Access

## Attack Timeline

## Key Findings

## Investigation Indicators

## MITRE ATT&CK Mapping

## Detection Opportunities

## Remediation Recommendations

## Evidence Limitations

## Skills Demonstrated