# Windows Threat Detection — Security Event and Sysmon Investigations

## Executive Summary

This project documents nine simulated Windows security investigations focused on detecting and analyzing suspicious activity using Windows Security event logs, Sysmon telemetry, and endpoint process evidence.

The investigations covered initial access, post-compromise discovery, data collection, command-and-control activity, and persistence.

Rather than relying exclusively on individual event IDs or detection alerts, I examined process relationships, command-line arguments, authentication activity, file operations, DNS queries, and Windows configuration changes to understand the behavior represented by each scenario.

The analysis included:

- **Initial access:** RDP authentication attacks, phishing-related executable delivery, and malware execution originating from removable media.
- **Discovery and collection:** Suspicious process trees, system and security-software discovery, clipboard collection, and potential data staging.
- **Command and control:** PowerShell-based payload retrieval, executable launch, and suspicious external communication.
- **Persistence:** Unauthorized local account creation, privileged-group membership changes, Windows service installation, and scheduled-task configuration.

The objective was to identify meaningful security events, correlate related evidence, distinguish attacker intent from confirmed outcomes, and translate the findings into actionable detection opportunities.

These investigations represent separate simulated scenarios grouped into a single defensive security case study. They do not describe one continuous intrusion.

## Investigation Scope

The investigation focused on three categories of Windows security monitoring.

| Category | Scenarios | Primary Focus |
| --- | --- | --- |
| Initial Access | RDP authentication, phishing-related execution, removable-media infection | Detecting suspicious access and initial malware execution |
| Discovery and Collection | Suspicious process ancestry, endpoint discovery, clipboard access, potential file staging | Identifying post-compromise information gathering and collection |
| Command and Control / Persistence | Payload delivery, backdoor accounts, Windows services, scheduled tasks | Investigating attacker communications and durable access mechanisms |

### Investigation Objectives

The analysis sought to answer several recurring questions:

1. What Windows events or process behaviors indicated suspicious activity?
2. Which event fields helped establish the affected user, process, host, or resource?
3. Could process ancestry, timestamps, and related artifacts connect multiple events?
4. Which activities represented confirmed outcomes, and which were only attempted?
5. What additional telemetry would strengthen the investigative conclusions?
6. How could the findings be converted into useful SOC detection logic?

## Evidence Sources and Analysis Methodology

### Evidence Sources

The investigations used Windows endpoint telemetry, including:

- **Windows Security events:** Authentication activity, account creation, and privileged-group membership changes.
- **Sysmon process events:** Process creation, parent-child relationships, and command-line arguments.
- **Sysmon DNS events:** Queries associated with suspicious executable activity.
- **File and configuration artifacts:** Executable paths, staging locations, service configuration, and scheduled-task details.

The specific events and fields varied by scenario. Each finding was evaluated using the evidence available for that investigation.

### Analysis Approach

The investigations followed a consistent process:

| Step | Analyst Activity |
| --- | --- |
| 1. Identify | Locate suspicious events, processes, authentication patterns, or configuration changes |
| 2. Pivot | Examine event IDs, users, process IDs, command lines, and related activity |
| 3. Correlate | Connect events through process ancestry, host context, timestamps, or affected resources |
| 4. Assess | Determine what the evidence establishes and identify plausible attacker objectives |
| 5. Document | Preserve relevant screenshots, indicators, and investigative conclusions |
| 6. Recommend | Identify detection opportunities and additional telemetry that could improve visibility |

### Evidence Standards

The analysis distinguishes between **observed commands**, **confirmed system events**, and **inferred attacker objectives**.

For example, a DNS query does not independently prove successful command-and-control communication or data transfer. Similarly, a process-creation event may show an attempted configuration change without establishing that the requested change succeeded.

Windows Security events confirming account creation or privileged-group membership provide stronger evidence of those specific outcomes.

Where screenshots or logs did not establish the result of an action, the investigation documents the activity without assuming success.

## Investigation Organization

The report is organized by threat behavior rather than by the order in which the training scenarios were completed.

The following sections examine:

1. Initial access through RDP, phishing-related execution, and removable media.
2. Discovery and collection through suspicious Windows process activity.
3. Command-and-control behavior involving PowerShell and external infrastructure.
4. Persistence through local accounts, services, and scheduled tasks.

Each scenario is evaluated independently, with cross-scenario observations reserved for the final detection and defensive-analysis sections.