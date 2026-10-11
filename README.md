# Detection & Response Investigations

A collection of hands-on cybersecurity investigations focused on Security Operations Center (SOC) analysis, threat detection, incident investigation, and defensive security monitoring.

These case studies document investigations conducted in controlled training environments using Windows Security logs, Sysmon, Linux auditd, Elastic/Kibana, Splunk, and network telemetry.

Each investigation emphasizes reconstructing suspicious activity from evidence, correlating related events, identifying attacker behaviors, and distinguishing confirmed findings from investigative hypotheses.

## Investigation Portfolio

| Investigation | Focus | Technologies |
| --- | --- | --- |
| [Multi-Stage Windows Intrusion — Tempest](investigations/tempest-windows-intrusion/README.md) | Investigating initial execution, command and control, privilege escalation, account manipulation, and persistence | Windows Security, Sysmon, network telemetry |
| [SOC Alert Triage — SOC Simulator](investigations/soc-alert-triage/README.md) | Alert investigation, suspicious discovery activity, sensitive-file access, and potential data exfiltration | SOC alert telemetry, endpoint evidence |
| [Windows Threat Detection](investigations/windows-threat-detection/README.md) | RDP authentication, malicious executables, system discovery, data collection, and persistence | Windows Security, Sysmon |
| [Linux Threat Detection](investigations/linux-threat-detection/README.md) | SSH compromise, web command injection, process reconnaissance, cryptominer activity, privilege escalation, and persistence | Linux authentication logs, Nginx, auditd |
| [Windows Process Investigation — Benign](investigations/windows-process-investigation/README.md) | Suspicious accounts, scheduled-task persistence, and living-off-the-land download activity | Splunk, Windows Event ID 4688 |
| [HTTP C2 Investigation — ItsyBitsy](investigations/http-c2-investigation/README.md) | HTTP traffic analysis, suspicious user agents, external IOC investigation, and potential C2 activity | Elastic/Kibana, HTTP telemetry |

## Technical Skills Demonstrated

**Security Monitoring & SIEM**
- Elastic Security and Kibana Discover
- Splunk investigation and event filtering
- Windows Security event analysis
- Sysmon endpoint telemetry
- Linux auditd and authentication-log analysis
- HTTP and network-event investigation

**Threat Detection & Investigation**
- Process-tree reconstruction and command-line analysis
- Suspicious authentication and account activity
- Web command injection and reverse-shell investigation
- Credential discovery and privilege escalation
- Scheduled-task, service, cron, and SSH-key persistence
- Command-and-control and potential exfiltration analysis

**Defensive Analysis & Reporting**
- MITRE ATT&CK technique mapping
- Behavioral detection recommendations
- Cross-source event correlation
- Indicator-of-compromise investigation
- Evidence preservation and documentation
- Evidence-backed conclusions and investigative limitations

## Investigation Methodology

The case studies follow a consistent analytical workflow:

1. **Identify** suspicious events, alerts, or behaviors.
2. **Investigate** the relevant logs, processes, commands, and network activity.
3. **Correlate** related evidence using timestamps, process relationships, users, and host context.
4. **Assess** what the evidence confirms and what remains uncertain.
5. **Document** findings with supporting screenshots and technical explanations.
6. **Recommend** defensive detection and monitoring opportunities.

The investigations distinguish observed activity from assumed attacker success. For example, a DNS request does not necessarily establish successful command-and-control communication, and a process-creation event does not guarantee that the operation requested by a command completed successfully.

## Evidence and Scope

The repository contains **six documented investigations supported by 62 evidence screenshots**.

Each investigation includes a dedicated README and numbered evidence files. The investigations were completed in controlled educational and simulated security environments, and their findings should not be interpreted as production incidents.

The case studies emphasize investigative methodology and technical reasoning rather than relying solely on scenario completion.

## Portfolio and Contact

Additional cybersecurity projects, hands-on labs, and technical work are available through:

- **Portfolio:** [Austin's Angle](https://austinsangle.com)
- **GitHub:** [github.com/abmathi](https://github.com/abmathi)