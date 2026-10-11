# Windows Process Investigation — Splunk Security Event Analysis

## Executive Summary

This project documents a simulated Windows security investigation using Splunk to analyze process-creation events and identify potentially malicious activity across multiple endpoints.

The investigation examined 13,959 Windows process events and identified three notable findings:

- **Suspicious account activity:** A look-alike username, `Amel1a`, resembling the legitimate account `Amelia`, appeared in the process-event data.
- **Scheduled-task persistence:** A suspicious `schtasks.exe` command attempted to configure an executable named `update.exe` to run at system startup.
- **Living-off-the-land activity:** The legitimate Windows utility `certutil.exe` was used in a command attempting to retrieve external content and save it as `benign.exe`.

The analysis focused on identifying unusual process behavior, reviewing command-line arguments, correlating activity with user accounts and hosts, and evaluating the evidence supporting each finding.

The objective was to distinguish suspicious commands from confirmed outcomes and develop practical detection opportunities using Windows Security event data.

The findings represent separate observations within a simulated investigation. The preserved evidence does not establish that all three activities were performed by the same attacker or formed one continuous intrusion.

## Investigation Scope

The investigation focused on Windows Security Event ID `4688`, which records process creation when the appropriate auditing is enabled.

Splunk was used to search process-event telemetry, investigate suspicious commands, and pivot between users, hostnames, and executable names.

| Investigation Area | Activity Examined | Primary Evidence |
| --- | --- | --- |
| Process Baseline | Windows process creation across users and hosts | Splunk search results, Event ID `4688` |
| Account Anomalies | Look-alike account `Amel1a` | Username enumeration and process searches |
| Scheduled-Task Persistence | `schtasks.exe` creating `OfficUpdater` | Process command-line evidence |
| Suspicious Download Activity | `certutil.exe` retrieving external content | Process command-line evidence |
| External IOC Investigation | `controlc.com/e4d11035` | Splunk findings and external resource pivot |

### Investigation Objectives

The investigation sought to answer the following questions:

1. What process activity stood out from the Windows event baseline?
2. Which user accounts and endpoints were associated with suspicious commands?
3. Did command-line arguments indicate persistence, reconnaissance, or external content retrieval?
4. Which observations represented confirmed process execution versus attempted operations?
5. Could related events establish subsequent payload execution or persistence?
6. What detection opportunities could be developed from the observed behaviors?

## Evidence Sources and Analysis Methodology

### Windows Process-Creation Events

The investigation used Windows Security Event ID `4688` as the primary source of process telemetry.

Relevant fields included:

- Process and executable names
- Command-line arguments, when available
- User accounts
- Computer names
- Process timestamps
- Parent-process context, where available

Event ID `4688` was useful for identifying which commands executed and which users or systems were associated with them.

However, a process-creation event does not independently establish that every operation requested by its command line succeeded.

### Splunk Investigation

Splunk was used to examine the event dataset and narrow the investigation from general process activity to specific suspicious behaviors.

The investigation followed a consistent approach:

| Step | Analyst Activity |
| --- | --- |
| Establish Baseline | Identify the event source, available fields, accounts, and hosts |
| Identify Anomalies | Locate unexpected usernames, executable names, or command arguments |
| Pivot | Search for related process events using users, hosts, and indicators |
| Correlate | Examine activity using timestamps and available process context |
| Assess | Separate confirmed execution from unverified outcomes |
| Document | Preserve relevant searches, findings, and screenshots |
| Recommend | Identify potential SOC detections and visibility improvements |

### Evidence Standards

The findings were evaluated based on what the preserved process events and investigation artifacts demonstrated.

For example:

- A suspicious username appearing in process logs does not independently establish that the account was created maliciously.
- Execution of `schtasks.exe` with task-creation arguments does not prove that the task was successfully registered.
- Execution of `certutil.exe` with download arguments does not independently confirm that the download completed.
- Failure to identify subsequent execution in the searched telemetry does not conclusively prove that an executable never ran.
- An external page containing suspicious content provides investigative context but does not automatically establish that the same content was successfully retrieved by the endpoint.

These distinctions were maintained to ensure that the investigation conclusions remained supported by observable evidence.

## Investigation Organization

The report documents four related areas of analysis:

1. **Process Event Baseline:** Establishing visibility into Windows process-creation activity using Splunk.
2. **Account Anomaly:** Investigating the look-alike username `Amel1a`.
3. **Scheduled-Task Persistence:** Examining the suspicious `OfficUpdater` task-creation command.
4. **External Content Retrieval:** Investigating `certutil.exe` activity and the associated external indicator.

The final sections consolidate detection opportunities, MITRE ATT&CK mappings, evidence limitations, and skills demonstrated.