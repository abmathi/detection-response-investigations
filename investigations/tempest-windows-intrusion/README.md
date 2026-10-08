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
### MSDT and Encoded PowerShell

## Stage 2 Payload and Persistence

### Payload Delivery
### Startup Persistence

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