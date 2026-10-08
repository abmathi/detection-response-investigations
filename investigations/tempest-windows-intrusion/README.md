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

Following initial execution, the attacker retrieved an additional payload using built-in Windows tooling.

Evidence showed `certutil.exe` being used to obtain a file later associated with continued attacker activity.

This represented a transition from the initial document-triggered execution into a second stage of the compromise.

The observed progression was consistent with:

```text
Initial PowerShell execution
        ↓
certutil.exe
        ↓
Remote payload retrieval
        ↓
Local executable
```

Because `certutil.exe` is a legitimate Windows utility, its presence alone was not treated as malicious.

Its significance came from the surrounding execution chain, the remote retrieval behavior, and the role of the downloaded file in subsequent attacker activity.

### Startup Persistence

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

### C2 Infrastructure
### HTTP Communication
### User-Agent Analysis

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