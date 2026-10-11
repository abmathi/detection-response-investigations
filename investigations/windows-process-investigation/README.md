# Windows Process Investigation — Splunk Security Event Analysis

## Executive Summary

This case study analyzes **13,959 Windows process-creation events** in Splunk to investigate three suspicious findings across a simulated enterprise environment: a look-alike user account, an attempted scheduled-task configuration, and external content retrieval using `certutil.exe`.

The investigation examined Windows Security Event ID `4688` to establish process execution, identify associated users and endpoints, and interpret command-line arguments. The key findings were:

- **Account anomaly:** `Amel1a` resembled the directory-listed user `Amelia`; investigation notes associated the look-alike account with `whoami.exe` execution.
- **Potential persistence:** `Chris.fort` on `HR_02` launched `schtasks.exe` with arguments to create a startup task named `OfficUpdater`, targeting `update.exe` in a user Temp directory.
- **Attempted external retrieval:** `haroon` on `HR_01` launched `certutil.exe` with an external resource at `controlc.com/e4d11035` and the intended output `benign.exe`.

These are **distinct findings**, not an established single intrusion chain. The preserved process telemetry confirms observed process execution but does not, by itself, confirm scheduled-task creation, successful file download, or payload execution.

## Investigation Scope and Methodology

| Area | Investigative Focus | Evidence |
| --- | --- | --- |
| Event baseline | Windows process activity and searchable fields | Splunk, Security Event ID `4688` |
| Account anomaly | `Amel1a` compared with `Amelia` | Investigation notes, process searches |
| Persistence attempt | `OfficUpdater` startup-task command | `schtasks.exe` command line |
| External retrieval | `certutil.exe` URL and intended output | Process command line, external-resource pivot |

Windows Security Event ID `4688` was the principal telemetry source. The investigation used Splunk to establish the event baseline, enumerate accounts and hosts, identify unusual commands, and pivot on executable names and indicators. Available fields included usernames, computer names, executable paths, command lines, and timestamps.

**Evidence standard:** A process-creation event confirms that a process started, not that the operation requested in its arguments completed successfully. Findings derived from investigation notes but lacking a dedicated screenshot are explicitly identified as such. The recommended detection strategies below were proposed, **not deployed or validated** in a production SIEM.

## Investigation Findings

### Finding 1 — Windows Process-Event Baseline

The initial Splunk review identified **13,959 process events** associated with Windows Security Event ID `4688`. This established a searchable dataset for investigating user activity, executable launches, and command-line arguments across hosts. The event count is a baseline measurement, not an indicator of compromise on its own.

![Splunk Windows process-event baseline](evidence/01-splunk-event-baseline.png)

*Figure 1 — Splunk process-event baseline using Windows Security Event ID 4688.*

**Assessment:** Process visibility was established for subsequent threat hunting. Additional context was necessary to distinguish routine activity from suspicious behavior.

### Finding 2 — Look-Alike Account: `Amel1a`

Username enumeration revealed `Amel1a`, which visually resembled `Amelia`, an account in the supplied employee directory. The difference was the numeral **`1`** in place of the letter **`i`**.

A follow-up Splunk search, documented in the preserved investigation notes, identified `whoami.exe` as the only process observed for `Amel1a` in the searched dataset. There was no dedicated screenshot of that search.

| Observation | Interpretation |
| --- | --- |
| `Amelia` appears in the employee directory | Expected identity for comparison |
| `Amel1a` appears in process telemetry | Look-alike account name requiring validation |
| `whoami.exe` observed for `Amel1a` | Possible user-context discovery, also common in legitimate workflows |
| No other processes identified in the search | Limited visibility, not proof of an absence of other activity |

**Assessment:** A suspicious account-name anomaly, **not confirmed impersonation or account compromise**. The data does not establish who created or controlled the account, whether it had elevated privileges, or why `whoami.exe` ran. Follow-up would require identity inventory, authentication history, account-creation events such as `4720`, and group-membership review.

### Finding 3 — Attempted Scheduled-Task Persistence

A March 6, 2022, Event ID `4688` record showed `schtasks.exe` activity associated with `Chris.fort` on `HR_02`. The command arguments requested a task named `OfficUpdater` to run `update.exe` from the user's Temp directory at startup.

| Indicator | Recorded Value |
| --- | --- |
| Account | `Chris.fort` |
| Host | `HR_02` |
| Date | March 6, 2022 |
| Utility | `schtasks.exe` |
| Task name | `OfficUpdater` |
| Intended executable | `update.exe` in a user Temp directory |
| Requested trigger | System startup |

![Suspicious scheduled-task creation command](evidence/02-scheduled-task-creation-command.png)

*Figure 2 — Splunk process event showing the `schtasks.exe` task-creation command associated with `Chris.fort` on `HR_02`.*

The updater-like task name and user-writable executable location made the command suspicious. However, Event ID `4688` does not establish that the `OfficUpdater` task was successfully registered, or that `update.exe` subsequently ran.

**Assessment:** **Attempted scheduled-task persistence.** Verify task registration using Security Event ID `4698` (if enabled), Task Scheduler Operational events, or the task definition itself before claiming confirmed persistence.

### Finding 4 — Suspicious `certutil.exe` Retrieval Command

On March 4, 2022, a process event associated with `haroon` on `HR_01` recorded `certutil.exe` with arguments referencing `controlc.com/e4d11035` and an intended output file named `benign.exe`.

| Indicator | Recorded Value |
| --- | --- |
| Account | `haroon` |
| Host | `HR_01` |
| Date | March 4, 2022 |
| Utility | `certutil.exe` |
| External resource | `controlc.com/e4d11035` |
| Intended output | `benign.exe` |

![Suspicious certutil command in Splunk](evidence/03-certutil-external-download-command.png)

*Figure 3 — Event ID 4688 showing `certutil.exe` with an external URL and intended executable output.*

Although `certutil.exe` is a legitimate Windows utility, its ability to retrieve remote files makes external-download arguments noteworthy. The process record establishes that the retrieval command was launched; it does **not** establish successful network transfer or file creation.

#### Execution and External-Resource Pivots

A search of the available process events found **no matching `benign.exe` process-creation record**. This is a scoped negative result: it does not prove that the file was never created or executed outside the searched telemetry.

The separate external-resource pivot showed content associated with `controlc.com/e4d11035`, including a `flag.txt` indicator. That page content was investigative context, **not endpoint evidence** that the requested content reached `HR_01`.

![External IOC investigation](evidence/04-controlc-ioc-pivot.png)

*Figure 4 — External-resource pivot related to the URL identified in the `certutil.exe` command.*

**Assessment:** **Attempted external content retrieval through a legitimate Windows binary.** Network/proxy logs and file-creation telemetry would be needed to confirm a successful transfer; additional process records would be needed to confirm execution of `benign.exe`.

## Detection Opportunities

The following rules are **recommendations**, not detections implemented or tested during this exercise.

| Use Case | Proposed Detection | Validation Source |
| --- | --- | --- |
| Look-alike identity | Compare newly observed usernames with approved identity inventory; prioritize names with small visual differences | Account inventory; Security `4720`; authentication logs |
| Suspicious user discovery | Examine `whoami.exe` executed by unexpected or newly observed accounts | Security `4688`; contextual user activity |
| Scheduled-task creation | Flag `schtasks.exe /create`, especially startup triggers pointing to Temp paths | Security `4688` plus `4698` and Task Scheduler logs |
| Unusual updater task | Review software-like task names pointing to user-writable executables | Task definitions; endpoint file telemetry |
| `certutil.exe` download | Detect `certutil.exe` invoking external URLs and executable output paths | Security `4688`; proxy/DNS/network telemetry |
| Download-to-execution correlation | Join retrieval commands to file-creation events and launches of the output filename | Sysmon file/process events, EDR, Security `4688` |

**High-value correlations:**

1. **Identity anomaly → discovery:** Unapproved account name closely matching a legitimate user, followed by `whoami.exe` or similar reconnaissance.
2. **Task-creation command → task registration:** `schtasks.exe /create` followed by a corresponding task-creation event or task XML entry.
3. **External retrieval → file and process activity:** Suspicious `certutil.exe` command followed by verified output-file creation and subsequent execution.

Detection thresholds and exceptions should account for authorized administration, software installers, and other legitimate use of Windows utilities.

## MITRE ATT&CK Mapping

| Finding | Technique | ID | Evidence Confidence |
| --- | --- | --- | --- |
| Look-alike account | Masquerading: Masquerade Account Name | `T1036.010` | **Hypothesis:** account resemblance observed; adversary intent not established |
| User discovery | System Owner/User Discovery | `T1033` | `whoami.exe` observed in investigation notes; purpose undetermined |
| Startup-task command | Scheduled Task/Job: Scheduled Task | `T1053.005` | Task-creation command observed; successful registration not confirmed |
| `certutil.exe` retrieval | Ingress Tool Transfer | `T1105` | Attempted external retrieval; transfer not confirmed |

These are behavior classifications, not proof that each technique was completed. In particular, the evidence does **not** support a separate System Binary Proxy Execution (`T1218`) claim: the observed `certutil.exe` behavior involved downloading, not demonstrated proxy execution. The account-name mapping is tentative without evidence of deliberate masquerading.

## Evidence Limitations

| Finding | Supported Observation | Not Established |
| --- | --- | --- |
| Event baseline | 13,959 process events available in Splunk | Any compromise from event volume alone |
| Look-alike account | `Amel1a` and `whoami.exe` identified in preserved notes | Account creator, intent, privileges, or compromise; no dedicated image |
| Scheduled task | `schtasks.exe` launched with `OfficUpdater` creation arguments | Task-registration success or execution at startup |
| External retrieval | `certutil.exe` launched with URL and target filename | Successful download, output-file creation, or execution |
| IOC pivot | External resource was viewed separately | Retrieval of that content by the endpoint |

**Analytical principle:** Event ID `4688` confirms process creation, not whether commands achieved their intended effects. Similarly, absence of a matching result from a bounded search does not establish that an event never occurred.

## Skills Demonstrated

- **Splunk and Windows monitoring:** Event ID `4688` searches, event baselining, user and endpoint pivots, command-line review.
- **Threat investigation:** Look-alike account analysis, scheduled-task persistence assessment, living-off-the-land utility investigation, external IOC pivoting.
- **Detection engineering concepts:** Event correlation, investigation hypotheses, ATT&CK mapping, evidence limitations, and proposed alert logic.

### Investigation Takeaway

This investigation illustrates why **process context matters more than an executable name alone**. `whoami.exe`, `schtasks.exe`, and `certutil.exe` have legitimate uses; anomalous account names, execution paths, command-line arguments, and related telemetry determine whether activity warrants escalation. Careful correlation allowed suspicious behaviors to be documented without overstating persistence, download success, or compromise.
