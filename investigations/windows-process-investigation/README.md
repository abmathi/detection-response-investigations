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

## Investigation Findings

### Finding 1 — Windows Process-Event Baseline

#### Investigation Context

The investigation began by examining Windows Security Event ID `4688` in Splunk to establish visibility into process execution across the available endpoints.

The dataset contained **13,959 process-creation events**.

Rather than immediately searching for a specific malicious executable, the initial analysis focused on identifying the available users, hosts, processes, and command-line fields.

This provided a baseline for subsequent investigative pivots.

#### Process Telemetry Analysis

Event ID `4688` records the creation of a new process when Windows process-creation auditing is enabled.

The Splunk investigation used this telemetry to examine process activity and identify potentially unusual behavior.

| Evidence | Investigative Significance |
| --- | --- |
| 13,959 process events | Established the size of the available process-event dataset |
| Event ID `4688` | Identified the Windows process-creation event source |
| User and computer fields | Supported attribution of activity to accounts and endpoints |
| Executable names | Enabled searches for suspicious or unusual processes |
| Command-line arguments | Provided context about what processes were instructed to do |

![Splunk Windows process-event baseline](evidence/01-splunk-event-baseline.png)

*Figure 1 — Splunk investigation of Windows Security Event ID 4688, establishing the process-event dataset and available fields for further analysis.*

The baseline helped narrow the investigation from general process activity to specific accounts and commands requiring further examination.

#### Analyst Assessment

**Assessment: Process-event visibility established for subsequent threat hunting.**

The baseline did not independently indicate a security incident. Its value was in providing a searchable dataset for identifying and investigating suspicious activity.

The following findings use this process telemetry to examine account anomalies, persistence-related commands, and external content retrieval.

### Finding 2 — Suspicious Look-Alike User Account

#### Investigation Context

During the Splunk process-event investigation, username enumeration revealed two visually similar account names:

- `Amelia` — a name present in the supplied employee directory.
- `Amel1a` — a similar name substituting the numeral `1` for the letter `i`.

The unexpected account name raised concern about potential identity impersonation or an account created to blend into normal user activity.

The investigation focused on determining what process activity was associated with the look-alike username.

#### Account and Process Analysis

The username comparison identified `Amel1a` as an anomaly relative to the known employee list.

A subsequent Splunk search examined process-creation events associated with that account.

The preserved investigation notes identified `whoami.exe` as the only process observed for `Amel1a` in the searched dataset.

| Observation | Investigative Significance |
| --- | --- |
| `Amelia` in employee directory | Expected identity used for comparison |
| `Amel1a` in process-event telemetry | Look-alike username requiring investigation |
| `whoami.exe` execution | Command commonly used to identify the current user |
| No other processes identified in the search | Limited visibility into the account's broader activity |

The execution of `whoami.exe` was consistent with user-context discovery, but it is also common during legitimate administration and troubleshooting.

The combination of a visually deceptive username and user-discovery activity made the account worth investigating. However, neither observation independently established malicious intent.

#### Analyst Assessment

**Assessment: Suspicious account-name anomaly with limited observed process activity.**

The available evidence supported the presence of a look-alike username and associated `whoami.exe` execution.

It did not establish how the account was created, who controlled it, whether its credentials were compromised, or whether it possessed elevated privileges.

The finding should therefore be treated as an identity anomaly requiring additional validation rather than confirmed account compromise.

#### Detection Opportunities

- Compare observed account names with approved identity inventories.
- Investigate newly observed usernames resembling legitimate employees or service accounts.
- Correlate suspicious account names with authentication and account-creation events.
- Review Windows Security Event ID `4720` where available to identify account creation.
- Monitor unexpected discovery commands performed by previously unseen accounts.
- Investigate account privileges, group memberships, and subsequent activity before determining severity.

### Finding 3 — Suspicious Scheduled-Task Persistence

#### Investigation Context

The investigation identified suspicious `schtasks.exe` execution associated with the Windows account `Chris.fort` on endpoint `HR_02`.

The process event was recorded on March 6, 2022, and contained command-line arguments indicating an attempt to create a scheduled task configured to launch an executable at system startup.

The investigation focused on identifying the requested task configuration and determining whether the available telemetry confirmed persistent execution.

#### Process and Command-Line Analysis

Windows Security Event ID `4688` recorded execution of `schtasks.exe`.

The command attempted to create a scheduled task named `OfficUpdater` that referenced an executable named `update.exe` in the user's temporary directory.

| Indicator | Observed Value |
| --- | --- |
| User | `Chris.fort` |
| Endpoint | `HR_02` |
| Date | March 6, 2022 |
| Process | `schtasks.exe` |
| Task name | `OfficUpdater` |
| Target executable | `update.exe` |
| Target location | User Temp directory |
| Requested trigger | System startup |

![Suspicious scheduled-task creation command](evidence/02-scheduled-task-creation-command.png)

*Figure 2 — Splunk Windows Security Event ID 4688 showing `schtasks.exe` activity associated with `Chris.fort` on `HR_02`, attempting to create the `OfficUpdater` startup task.*

The task name resembled legitimate office software maintenance activity, while the executable's temporary-directory location was unusual for a trusted updater.

The combination of a software-update-themed task name, startup trigger, and executable in a user-writable location was consistent with an attempted persistence mechanism.

#### Analyst Assessment

**Assessment: Suspicious scheduled-task creation command consistent with attempted persistence.**

The preserved process telemetry confirmed that `schtasks.exe` was launched with arguments requesting scheduled-task creation.

However, Event ID `4688` records process creation, not the success or failure of the task-registration operation.

The investigation did not independently establish that `OfficUpdater` was successfully registered, executed at startup, or launched `update.exe`.

#### Detection Opportunities

- Monitor `schtasks.exe` execution containing task-creation arguments.
- Investigate newly created tasks configured to execute at startup or user logon.
- Alert on scheduled tasks referencing executables in user-writable directories.
- Correlate suspicious process creation with Windows Security Event ID `4698`, where task-creation auditing is enabled.
- Review Task Scheduler Operational logs and task definitions to validate registration and execution.
- Investigate task names that imitate legitimate software or operating-system components.
