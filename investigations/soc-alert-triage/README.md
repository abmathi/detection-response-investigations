# SOC Alert Triage — PowerShell Intrusion and Suspected DNS Exfiltration

## Executive Summary

This project documents a simulated Security Operations Center (SOC) investigation involving suspicious PowerShell activity, network-share access, potential data staging, and DNS traffic consistent with a possible exfiltration attempt.

The investigation began with alerts presented through a SOC simulation environment. Rather than treating each alert as an isolated incident, I correlated endpoint activity to identify relationships between suspicious processes, file operations, network connections, and potential attacker objectives.

A central finding was the relationship between PowerShell process ID `3728` and several subsequent activities, including local directory creation, access to a financial records network share, file collection using Robocopy, and repeated DNS lookups.

Additional investigation notes identified Powercat-related activity involving an external relay destination and a separate PowerShell process creating a PowerView script.

The combined evidence supported an assessment of suspicious post-compromise activity involving potential data collection and exfiltration. However, the preserved evidence did not independently confirm that data was successfully received by an external destination.

The investigation demonstrates practical SOC responsibilities including alert prioritization, process correlation, event investigation, true-positive classification, and evidence-based escalation decisions.

## Investigation Scope

The investigation focused on determining whether multiple alerts represented unrelated system activity or a connected sequence of potentially malicious behavior.

The primary investigative questions were:

- What triggered the initial security alerts?
- Which processes were associated with suspicious activity?
- Could multiple alerts be correlated to a common execution context?
- Was sensitive information accessed or staged?
- Did the observed network activity indicate potential exfiltration?
- Which alerts warranted true-positive classification and escalation?
- What conclusions could be established from the preserved evidence?

### Investigation Environment

The analysis was conducted in a simulated SOC environment using an alert queue and Elastic SIEM telemetry.

Available evidence included:

- Security alert details and classifications
- Windows process activity and command-line information
- File-creation observations
- Network-share access and file-copy activity
- DNS-related investigation notes
- Screenshots of selected alert investigations
- Simulator performance results

The investigation centered on Windows endpoint `win-3450`, with process IDs and command-line activity used to correlate related events.

### Evidence Limitations

The simulator concluded after a final group of alerts was classified as true positive, leaving limited opportunity to preserve additional screenshots.

As a result, this report distinguishes between findings directly illustrated by preserved screenshots and observations recorded in contemporaneous investigation notes.

Where network activity suggested data exfiltration, the assessment is described as suspected rather than confirmed unless the supporting evidence established successful external data transfer.

The purpose of the case study is to demonstrate the investigative reasoning and alert-handling decisions made during the simulation, not to imply access to telemetry or response actions that were not preserved.

## Alert Triage and Initial Investigation

### Initial Alert Queue

The investigation began in a simulated SOC alert queue containing security detections requiring analyst review and classification.

The initial evidence included phishing-related alert context. Rather than making a classification based on the alert title alone, I examined the available alert details to understand the suspected activity and determine whether additional investigation was warranted.

The triage process focused on three questions:

1. **What triggered the alert?** Identify the reported activity, affected endpoint, and available indicators.
2. **What supporting evidence exists?** Review associated process, file, and network telemetry.
3. **Does the evidence justify escalation?** Determine whether the activity is benign, suspicious, or consistent with a genuine security incident.

![Initial SOC alert queue](evidence/01-initial-alert-queue.png)

*Figure 1 — Initial SOC simulation alert queue showing phishing-related detection context and available analyst triage actions.*

### Moving Beyond Individual Alerts

As additional detections appeared, the investigation expanded beyond the initial alert context.

Several alerts involved suspicious PowerShell activity and subsequent file-system or network operations on the Windows endpoint `win-3450`.

The investigation therefore shifted toward identifying relationships between the alerts rather than evaluating each detection independently.

Process identifiers, command-line arguments, affected resources, and event context were used to determine whether the detections could represent different stages of a connected intrusion.

### Investigation Approach

The analysis followed a repeatable SOC triage workflow:

| Stage | Analyst Activity | Purpose |
| --- | --- | --- |
| Alert Review | Examine detection details and affected systems | Establish initial context |
| Evidence Collection | Review associated endpoint and network telemetry | Identify supporting observations |
| Process Correlation | Compare process IDs and related commands | Connect potentially related events |
| Activity Assessment | Evaluate the behavior and possible attacker objectives | Determine whether activity is suspicious |
| Classification | Record true-positive or false-positive decisions | Resolve or escalate alerts based on evidence |
| Documentation | Preserve findings and supporting screenshots | Maintain a defensible investigation record |

### Initial Assessment

The alert queue was treated as the starting point of the investigation, not as proof that every detection represented a confirmed compromise.

The strongest investigative value came from correlating later PowerShell, file-access, and network activity.

That correlation is examined in the following sections, beginning with a PowerShell process that appeared repeatedly across the investigation.